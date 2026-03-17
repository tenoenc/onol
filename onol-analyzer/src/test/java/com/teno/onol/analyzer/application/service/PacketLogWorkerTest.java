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
    @DisplayName("TCP 필터링: 제어 패킷이나 초반 10개 패킷은 저장하고, 단순 데이터 패킷(Tail)은 버려야 한다")
    void should_SaveOnlyImportantTcpPackets_When_TcpBatchReceived() {
        // given
        PacketEvent head = PacketEvent.builder().protocol("TCP").srcPort(10001).timestamp(Instant.now()).build();
        PacketEvent tailData = PacketEvent.builder().protocol("TCP").srcPort(10002).timestamp(Instant.now()).build();
        PacketEvent tailFin = PacketEvent.builder().protocol("TCP").srcPort(10003).tcpFlags(PacketEvent.FLAG_FIN)
                .timestamp(Instant.now()).build();

        List<PacketEvent> batch = List.of(head, tailData, tailFin);

        // Redis Count Mocking: Head(1), TailData(11), TailFin(100)
        mockPacketCounts(List.of(1L, 11L, 100L));

        // when
        packetLogWorker.filterAndSaveAsync(batch);

        // then
        verify(savePacketLogPort).saveAll(argThat(logs -> {
            boolean hasHead = logs.stream().anyMatch(l -> l.getSrcPort() == 10001);
            boolean hasFin = logs.stream().anyMatch(l -> l.getSrcPort() == 10003);
            boolean hasTailData = logs.stream().anyMatch(l -> l.getSrcPort() == 10002);

            // Tail Data만 없어야 함
            return hasHead && hasFin && !hasTailData && logs.size() == 2;
        }));
    }

    @Test
    @DisplayName("UDP 필터링: DNS나 초반 10개 패킷은 저장하고, 10개 이후의 스트리밍 데이터는 버려야 한다")
    void should_SaveOnlyImportantUdpPackets_When_UdpBatchReceived() {
        // given
        // 1. DNS (Port 53) -> 카운트가 많아도(100) 무조건 저장
        PacketEvent dns = PacketEvent.builder().protocol("UDP").dstPort(53).srcPort(20001).timestamp(Instant.now()).build();

        // 2. New Stream (QUIC Start) -> 카운트 적음(1) -> 저장
        PacketEvent quicHead = PacketEvent.builder().protocol("UDP").dstPort(443).srcPort(20002).timestamp(Instant.now()).build();

        // 3. Heavy Stream (YouTube Data) -> 카운트 많음(100) -> 버림
        PacketEvent quicTail = PacketEvent.builder().protocol("UDP").dstPort(443).srcPort(20003).timestamp(Instant.now()).build();

        List<PacketEvent> batch = List.of(dns, quicHead, quicTail);

        // Redis Count Mocking: DNS(100), Head(1), Tail(100)
        mockPacketCounts(List.of(100L, 1L, 100L));

        // when
        packetLogWorker.filterAndSaveAsync(batch);

        // then
        verify(savePacketLogPort).saveAll(argThat(logs -> {
            boolean hasDns = logs.stream().anyMatch(l -> l.getSrcPort() == 20001);
            boolean hasHead = logs.stream().anyMatch(l -> l.getSrcPort() == 20002);
            boolean hasTail = logs.stream().anyMatch(l -> l.getSrcPort() == 20003);

            // Tail만 없어야 함
            return hasDns && hasHead && !hasTail && logs.size() == 2;
        }));
    }

    // 순서대로 카운트를 반환하도록 Mock 설정
    private void mockPacketCounts(List<Long> counts) {
        when(resolveGeoIpPort.resolveCountryCode(any())).thenReturn("KR"); // GeoIP는 기본 설정

        when(sessionStatePort.incrementPacketCounts(anyList())).thenAnswer(invocation -> {
            List<String> keys = invocation.getArgument(0);
            Map<String, Long> result = new HashMap<>();
            for (int i = 0; i < keys.size(); i++) {
                if (i < counts.size()) {
                    result.put(keys.get(i), counts.get(i));
                }
            }
            return result;
        });
    }
}