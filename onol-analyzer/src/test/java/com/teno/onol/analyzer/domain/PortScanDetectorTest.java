package com.teno.onol.analyzer.domain;

import com.teno.onol.core.domain.PacketEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.SetOperations;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.io.Serializable;
import java.time.Duration;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class PortScanDetectorTest {

    @Mock
    private StringRedisTemplate redisTemplate;

    private PortScanDetector detector;

    @BeforeEach
    void setUp() {
        detector = new PortScanDetector(redisTemplate, 5);
    }

    @Test
    @DisplayName("서로 다른 포트 접속이 임계치(5)에 도달하면 해당 IP를 탐지해야 한다")
    void should_Detect_When_DistinctPortsReachThreshold() {
        // given
        String attackerIp = "1.2.3.4";
        List<PacketEvent> packets = List.of(
                createPacket(attackerIp, 80) // 1개 들어옴
        );

        // Pipelining 결과 Mocking
        // 실제 로직: SADD(1), EXPIRE(true), SCARD(5) 순서로 리턴됨
        // 리스트 구조: [Long(added), Boolean(expired), Long(count)]
        List<Object> mockPipelineResult = List.of(1L, true, 5L); // 5개 도달 시뮬레이션

        when(redisTemplate.executePipelined(any(RedisCallback.class)))
                .thenReturn(mockPipelineResult);

        // when
        Set<String> detectedIps = detector.detectScanners(packets);

        // then
        assertThat(detectedIps).contains(attackerIp);
    }

    @Test
    @DisplayName("이미 임계치를 넘은 상태(6개)에서는 중복 탐지하지 않아야 한다 (알림 폭탄 방지)")
    void should_NotDetect_When_ThresholdAlreadyExceeded() {
        // given
        String attackerIp = "1.2.3.4";
        List<PacketEvent> packets = List.of(createPacket(attackerIp, 443));

        // Pipelining 결과 Mocking (이미 6개)
        List<Object> mockPipelineResult = List.of(1L, true, 6L);

        when(redisTemplate.executePipelined(any(RedisCallback.class)))
                .thenReturn(mockPipelineResult);

        // when
        Set<String> detectedIps = detector.detectScanners(packets);

        // then
        assertThat(detectedIps).isEmpty(); // 이미 알림 보냈을 테니 이번엔 조용히.
    }

    private PacketEvent createPacket(String srcIp, int dstPort) {
        return PacketEvent.builder()
                .srcIp(srcIp)
                .dstPort(dstPort)
                .protocol("TCP")
                .build();
    }

}
