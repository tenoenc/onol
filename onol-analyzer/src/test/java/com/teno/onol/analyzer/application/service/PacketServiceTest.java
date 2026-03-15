package com.teno.onol.analyzer.application.service;

import com.teno.onol.analyzer.application.port.out.ManageSessionStatePort;
import com.teno.onol.analyzer.application.port.out.RecordRealtimeMetricPort;
import com.teno.onol.analyzer.domain.PortScanDetector;
import com.teno.onol.analyzer.domain.TcpSessionTracker;
import com.teno.onol.core.domain.PacketEvent;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Collections;
import java.util.List;

import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PacketServiceTest {

    @Mock private RecordRealtimeMetricPort recordRealtimeMetricPort;
    @Mock private ManageSessionStatePort manageSessionStatePort;
    @Mock private PortScanDetector portScanDetector;
    @Spy private TcpSessionTracker tcpSessionTracker = new TcpSessionTracker();

    @Mock private PacketLogWorker packetLogWorker;

    @InjectMocks
    private PacketService packetService;

    @Test
    @DisplayName("패킷 수신 시 동기 작업(메트릭, 위협탐지, 세션 추적)을 완료한 후, 워커에게 저장을 위임해야 한다")
    void should_PerformSyncTasksAndDelegateToWorker_When_PacketsReceived() {
        // given
        List<PacketEvent> batch = List.of(
                PacketEvent.builder()
                        .timestamp(Instant.now())
                        .srcIp("1.1.1.1")
                        .protocol("TCP")
                        .tcpFlags(PacketEvent.FLAG_SYN)
                        .build()
        );

        // Mocking: 세션 상태 조회가 호출될 것임
        when(manageSessionStatePort.getSessionStates(anyList())).thenReturn(Collections.emptyMap());

        // when
        packetService.recordPackets(batch);

        // then
        // 1. 실시간 메트릭 (동기)
        verify(recordRealtimeMetricPort, times(1)).incrementMetrics(batch);

        // 2. 위협 탐지 (동기)
        verify(portScanDetector, times(1)).detectScanners(anyList());

        // 3. 세션 상태 추적 (동기)
        verify(manageSessionStatePort, times(1)).getSessionStates(anyList());
        verify(manageSessionStatePort, times(1)).updateSessionStates(anyMap());

        // 4. 마지막으로 워커에게 토스했는지 확인 (비동기)
        verify(packetLogWorker, times(1)).filterAndSaveAsync(batch);
    }

    @Test
    @DisplayName("TCP 패킷이 들어오면 트래커를 통해 상태를 계산하고 Redis 포트에 저장해야 한다")
    void should_OrchestrateSessionTracking_When_TcpPacketReceived() {
        // given
        PacketEvent tcpPacket = PacketEvent.builder()
                .timestamp(Instant.now())
                .srcIp("1.1.1.1").srcPort(1000)
                .dstIp("2.2.2.2").dstPort(80)
                .protocol("TCP")
                .tcpFlags(PacketEvent.FLAG_SYN)
                .build();

        // Redis에 기존 상태가 없다고 가정
        when(manageSessionStatePort.getSessionStates(anyList()))
                .thenReturn(Collections.emptyMap());

        // when
        packetService.recordPackets(List.of(tcpPacket));

        // then
        // updateSessionStates가 호출되었고, 그 인자(Map) 안에 'SYN_SENT'가 들어있는지 확인
        verify(manageSessionStatePort, times(1))
                .updateSessionStates(argThat(map -> map.containsValue("SYN_SENT")));
    }
}