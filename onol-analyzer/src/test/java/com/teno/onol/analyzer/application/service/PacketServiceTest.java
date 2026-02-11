package com.teno.onol.analyzer.application.service;

import com.teno.onol.analyzer.application.port.out.ManageSessionStatePort;
import com.teno.onol.analyzer.application.port.out.RecordRealtimeMetricPort;
import com.teno.onol.analyzer.application.port.out.ResolveGeoIpPort;
import com.teno.onol.analyzer.application.port.out.SavePacketLogPort;
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
import java.util.List;
import java.util.Set;

import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PacketServiceTest {

    @Mock private SavePacketLogPort savePacketLogPort;
    @Mock private ResolveGeoIpPort resolveGeoIpPort;
    @Mock private RecordRealtimeMetricPort recordRealtimeMetricPort;
    @Mock private ManageSessionStatePort manageSessionStatePort;
    @Mock private PortScanDetector portScanDetector;

    @Spy
    private TcpSessionTracker tcpSessionTracker = new TcpSessionTracker();

    @InjectMocks
    private PacketService packetService;

    @Test
    @DisplayName("패킷 리스트를 받으면 메트릭집계, 위협탐지, GeoIP변환, 저장을 모두 수행해야 한다")
    void should_ExecuteAllPipelineSteps_When_PacketsReceived() {
        // given
        List<PacketEvent> batch = List.of(
                PacketEvent.builder()
                        .timestamp(Instant.now())
                        .srcIp("1.1.1.1")
                        .protocol("TCP")
                        .build()
        );

        // GeoIP Mocking (KR 리턴)
        when(resolveGeoIpPort.resolveCountryCode("1.1.1.1")).thenReturn("KR");

        // PortScanDetector Mocking
        when(portScanDetector.detectScanners(anyList())).thenReturn(Set.of());

        // when
        packetService.recordPackets(batch);

        // then (호출 순서 및 횟수 검증)
        // 1. 실시간 메트릭 집계 호출 확인
        verify(recordRealtimeMetricPort, times(1)).incrementMetrics(batch);

        // 2. 위협 탐지 로직 호출 확인
        // PacketService 내부 구현에 따라 메서드 시그니처가 다를 수 있으므로 조정 필요
        verify(portScanDetector, times(1)).detectScanners(anyList());

        // 3. GeoIP 변환 호출 확인
        verify(resolveGeoIpPort, times(1)).resolveCountryCode("1.1.1.1");

        // 4. DB 저장 호출 확인
        verify(savePacketLogPort, times(1)).saveAll(anyList());
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

        // GeoIP Stubbing
        when(resolveGeoIpPort.resolveCountryCode(anyString())).thenReturn("KR");

        // Redis에 기존 상태가 없다고 가정
        when(manageSessionStatePort.getSessionState(anyString())).thenReturn(null);

        // when
        packetService.recordPackets(List.of(tcpPacket));

        // then
        // 트래커가 계산한 결과('SYN_SENT')를 Redis 포트에 저장했는지 검증
        verify(manageSessionStatePort, times(1))
                .updateSessionState(anyString(), eq("SYN_SENT"));
    }
}