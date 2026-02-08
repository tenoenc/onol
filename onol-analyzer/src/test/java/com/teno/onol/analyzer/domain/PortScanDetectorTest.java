package com.teno.onol.analyzer.domain;

import com.teno.onol.core.domain.PacketEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.SetOperations;
import org.springframework.data.redis.core.StringRedisTemplate;

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

    @Mock
    private SetOperations<String, String> setOperations;

    private PortScanDetector detector;

    @BeforeEach
    void setUp() {
        when(redisTemplate.opsForSet()).thenReturn(setOperations);

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

        // Redis Mock 동작 정의
        // 1. add는 1(새로운 값)을 반환한다고 가정
        given(setOperations.add(anyString(), anyString())).willReturn(1L);
        // 2. size를 호출했더니 딱 5개가 되었다고 가정 (임계치 도달)
        given(setOperations.size("threat:scan:" + attackerIp)).willReturn(5L);

        // when
        Set<String> detectedIps = detector.detectScanners(packets);

        // then
        assertThat(detectedIps).contains(attackerIp);

        // Redis 만료 시간 설정이 호출되었는지 검증 (Stateful의 핵심)
        verify(redisTemplate).expire(eq("threat:scan:" + attackerIp), any(Duration.class));
    }

    @Test
    @DisplayName("이미 임계치를 넘은 상태(6개)에서는 중복 탐지하지 않아야 한다 (알림 폭탄 방지)")
    void should_NotDetect_When_ThresholdAlreadyExceeded() {
        // given
        String attackerIp = "1.2.3.4";
        List<PacketEvent> packets = List.of(createPacket(attackerIp, 443));

        given(setOperations.add(anyString(), anyString())).willReturn(1L);
        // 이미 6개째 포트가 쌓여있음
        given(setOperations.size("threat:scan:" + attackerIp)).willReturn(6L);

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
