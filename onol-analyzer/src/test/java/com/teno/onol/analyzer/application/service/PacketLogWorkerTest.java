package com.teno.onol.analyzer.application.service;

import com.teno.onol.analyzer.application.port.out.ManageSessionStatePort;
import com.teno.onol.analyzer.application.port.out.ResolveGeoIpPort;
import com.teno.onol.analyzer.application.port.out.SavePacketLogPort;
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PacketLogWorkerTest {

    @Mock
    private ManageSessionStatePort sessionStatePort;
    @Mock private SavePacketLogPort savePacketLogPort;
    @Mock private ResolveGeoIpPort resolveGeoIpPort;
    @Spy private TcpSessionTracker tcpSessionTracker = new TcpSessionTracker();

    @InjectMocks
    private PacketLogWorker packetLogWorker;

    @Test
    @DisplayName("섞인 배치가 들어왔을 때 중요한 패킷(Head, Control, UDP)만 골라서 저장해야 한다")
    void should_SaveOnlyImportantPackets_When_MixedBatchReceived() {
        // 각 패킷의 srcPort를 다르게 해서 서로 다른 Flow Key가 생성되도록 유도

        // given
        // Case 1: [Head] 이제 막 시작한 패킷 (Count: 1) -> 저장 대상
        PacketEvent headPacket = PacketEvent.builder()
                .srcIp("1.1.1.1").dstPort(80).srcPort(10001)
                .protocol("TCP")
                .timestamp(Instant.now())
                .build();

        // Case 2: [Tail & Noise] 이미 많이 보낸 데이터 패킷 (Count: 11) -> 삭제 대상
        PacketEvent tailDataPacket = PacketEvent.builder()
                .srcIp("1.1.1.1").dstPort(80).srcPort(10002)
                .protocol("TCP")
                .timestamp(Instant.now())
                .build();

        // Case 3: [Tail & Control] 많이 보냈지만 연결 종료 패킷 (Count: 100 + FIN) -> 저장 대상
        PacketEvent tailControlPacket = PacketEvent.builder()
                .srcIp("1.1.1.1").dstPort(80).srcPort(10003)
                .protocol("TCP")
                .tcpFlags(PacketEvent.FLAG_FIN)
                .timestamp(Instant.now())
                .build();

        // Case 4: [UDP] TCP가 아닌 패킷 -> 무조건 저장 대상
        PacketEvent udpPacket = PacketEvent.builder()
                .srcIp("1.1.1.1").dstPort(53).protocol("UDP")
                .timestamp(Instant.now())
                .build();

        List<PacketEvent> batch = List.of(headPacket, tailDataPacket, tailControlPacket, udpPacket);

        // GeoIP Stubbing
        when(resolveGeoIpPort.resolveCountryCode(any())).thenReturn("KR");

        // Redis가 알려주는 누적 패킷 수 시뮬레이션
        // 순서대로: 1(Head), 11(Tail), 100(Tail) 리턴

        // 실제 구현에선 키가 각각 다르겠지만, 테스트에선 키 생성 로직을 타서 나온 키에 매핑해줌
        // 여기서는 편의상 서비스가 내부적으로 키를 생성했으므로,
        // incrementPacketCounts가 호출될 때 기대하는 카운트 맵을 리턴하도록 설정
        when(sessionStatePort.incrementPacketCounts(anyList())).thenAnswer(invocation -> {
            List<String> keys = invocation.getArgument(0);
            Map<String, Long> result = new HashMap<>();

            // 입력된 키 순서대로 카운트 매핑
            // keys[0]: headPacket (Port 10001) -> 1L
            // keys[1]: tailDataPacket (Port 10002) -> 11L
            // keys[2]: tailControlPacket (Port 10003) -> 100L
            if (keys.size() >= 3) {
                result.put(keys.get(0), 1L);
                result.put(keys.get(1), 11L);
                result.put(keys.get(2), 100L);
            }
            return result;
        });

        // when
        packetLogWorker.filterAndSaveAsync(batch);

        // then
        // saveAll에 전달된 리스트를 캡처해서 검증
        verify(savePacketLogPort, times(1)).saveAll(argThat(logs -> {
            // 총 4개 중 1개(tailDataPacket)는 버려지고 3개만 남아야 함
            if (logs.size() != 3) return false;

            // 남은 것들이 기대한 저장 대상인지 확인
            boolean hasHead = logs.stream().anyMatch(l -> l.getSrcPort() == 10001); // headPacket
            boolean hasFin = logs.stream().anyMatch(l -> l.getSrcPort() == 10003); // tailControlPacket
            boolean hasUdp = logs.stream().anyMatch(l -> l.getProtocol() == 17); // udpPacket

            return hasHead && hasFin && hasUdp;
        }));
    }
}