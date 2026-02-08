package com.teno.onol.analyzer.domain;

import com.teno.onol.core.domain.PacketEvent;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

public class TcpSessionTrackerTest {

    private final TcpSessionTracker tracker = new TcpSessionTracker();

    @Test
    @DisplayName("SYN 패킷이 오면 다음 상태는 SYN_SENT여야 한다")
    void should_ReturnSynSent_When_SynPacketReceived() {
        // given
        PacketEvent synPacket = PacketEvent.builder()
                .srcIp("1.1.1.1").srcPort(1000)
                .dstIp("2.2.2.2").dstPort(80)
                .timestamp(Instant.now()).protocol("TCP")
                .tcpFlags(PacketEvent.FLAG_SYN)
                .build();

        // when
        String nextState = tracker.determineNextState("NONE", synPacket);

        // then
        assertThat(nextState).isEqualTo("SYN_SENT");
    }

    @Test
    @DisplayName("SYN_SENT 상태에서 ACK 패킷이 오면 ESTABLISHED로 갱신해야 한다")
    void should_UpdateToEstablished_When_AckReceived_And_CurrentIsSynSent() {
        // given
        PacketEvent ackPacket = PacketEvent.builder()
                .srcIp("1.1.1.1").srcPort(1000)
                .dstIp("2.2.2.2").dstPort(80)
                .timestamp(Instant.now()).protocol("TCP")
                .tcpFlags(PacketEvent.FLAG_ACK)
                .build();

        // when
        String nextState = tracker.determineNextState("SYN_SENT", ackPacket);

        // then
        assertThat(nextState).isEqualTo("ESTABLISHED");
    }

    @Test
    @DisplayName("패킷의 방향이 반대여도(Server->Client) 동일한 세션으로 식별해야 한다")
    void should_IdentifySameSession_When_PacketDirectionFlips() {
        // given
        // 1. Client -> Server (SYN)
        PacketEvent synPacket = PacketEvent.builder()
                .srcIp("1.1.1.1").srcPort(1000)
                .dstIp("2.2.2.2").dstPort(80)
                .tcpFlags(PacketEvent.FLAG_SYN)
                .build();

        // 2. Server -> Client (SYN+ACK) : IP와 Port가 반대로 뒤집힘
        PacketEvent synAckPacket = PacketEvent.builder()
                .srcIp("2.2.2.2").srcPort(80)   // Src가 2.2.2.2
                .dstIp("1.1.1.1").dstPort(1000) // Dst가 1.1.1.1
                .tcpFlags(PacketEvent.FLAG_SYN | PacketEvent.FLAG_ACK)
                .build();

        // when
        String state = tracker.determineNextState("SYN_SENT", synPacket);// 상태: SYN_SENT 저장
        String nextState = tracker.determineNextState(state, synAckPacket); // 뒤집힌 패킷으로 조회

        // then
        // 키가 같아야만 SYN_SENT 상태를 이어서 ESTABLISHED로 갈 수 있음
        assertThat(nextState).isEqualTo("ESTABLISHED");
    }
}
