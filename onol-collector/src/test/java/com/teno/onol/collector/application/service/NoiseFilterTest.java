package com.teno.onol.collector.application.service;

import com.teno.onol.core.domain.PacketEvent;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

public class NoiseFilterTest {

    private final NoiseFilter noiseFilter = new NoiseFilter();

    @Test
    @DisplayName("로컬 루프백(127.0.0.1) 트래픽은 노이즈로 간주하여 차단해야 한다")
    void should_ReturnTrue_When_LoopbackTrafficIsDetected() {
        // given
        Instant ts = Instant.now();
        PacketEvent loopbackPacket = PacketEvent.builder()
                .timestamp(ts)
                .srcIp("127.0.0.1")
                .dstIp("127.0.0.1")
                .srcPort(12345)
                .dstPort(8080)
                .protocol("TCP")
                .build();

        // when
        boolean isNoise = noiseFilter.isNoise(loopbackPacket);

        // then
        assertThat(isNoise).isTrue();
    }

    @Test
    @DisplayName("Kafka(9092)나 DB(5432)와 통신하는 시스템 내부 트래픽은 차단해야 한다 (피드백 루프 방지)")
    void should_ReturnTrue_When_TrafficTargetsInfrastructurePorts() {
        // given: 목적지 포트가 Kafka(9092)
        Instant ts1 = Instant.now();
        PacketEvent kafkaPacket = PacketEvent.builder()
                .timestamp(ts1)
                .srcIp("192.168.0.5")
                .dstIp("192.168.0.10")
                .srcPort(50000)
                .dstPort(9092)
                .protocol("TCP")
                .build();

        // given: 목적지 포트가 TimescaleDB(5432)
        Instant ts = Instant.now();
        PacketEvent dbPacket = PacketEvent.builder()
                .timestamp(ts)
                .srcIp("192.168.0.5")
                .dstIp("192.168.0.10")
                .srcPort(60000)
                .dstPort(5432)
                .protocol("TCP")
                .build();

        // then
        assertThat(noiseFilter.isNoise(kafkaPacket)).isTrue();
        assertThat(noiseFilter.isNoise(dbPacket)).isTrue();
    }

    @Test
    @DisplayName("일반적인 외부 인터넷 트래픽은 통과시켜야 한다")
    void should_ReturnFalse_When_NormalExternalTrafficIsDetected() {
        // given: Google DNS(8.8.8.8)로 가는 트래픽
        Instant ts = Instant.now();
        PacketEvent normalPacket = PacketEvent.builder()
                .timestamp(ts)
                .srcIp("192.168.0.5")
                .dstIp("8.8.8.8")
                .srcPort(12345)
                .dstPort(53)
                .protocol("UDP")
                .build();

        assertThat(noiseFilter.isNoise(normalPacket)).isFalse();
    }

}
