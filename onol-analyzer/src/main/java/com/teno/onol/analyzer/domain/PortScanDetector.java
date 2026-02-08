package com.teno.onol.analyzer.domain;

import com.teno.onol.core.domain.PacketEvent;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Component
public class PortScanDetector {

    private final StringRedisTemplate redisTemplate;
    private final int threshold;

    private static final Duration DETECTION_WINDOW = Duration.ofMinutes(5);
    private static final String KEY_PREFIX = "threat:scan:";

    public PortScanDetector(StringRedisTemplate redisTemplate,
                            @Value("${onol.analyze.port-scan-threshold:20}") int threshold) {
        this.redisTemplate = redisTemplate;
        this.threshold = threshold;
    }

    /**
     * @return 스캔이 감지된 공격자 IP 목록 (중복 제거)
     */
    public Set<String> detectScanners(List<PacketEvent> packets) {
        if (packets.isEmpty()) return Set.of();

        // 1. IP별 접속 포트 수집 (Batch 내 집계)
        return packets.stream()
                .filter(p -> "TCP".equalsIgnoreCase(p.protocol()) || "UDP".equalsIgnoreCase(p.protocol()))
                .filter(p -> p.srcPort() != 53)
                .map(event -> checkThreat(event.srcIp(), event.dstPort()))
                .filter(Objects::nonNull) // null이 아니면 캄지된 IP
                .collect(Collectors.toSet());
    }

    public String checkThreat(String srcIp, int dstPort) {
        String key = KEY_PREFIX + srcIp;
        String portStr = String.valueOf(dstPort);

        try {
            // 1. Redis Set에 포트 추가 (SADD)
            Long addedCount = redisTemplate.opsForSet().add(key, portStr);

            // 2. TTL 갱신 (EXPIRE)
            redisTemplate.expire(key, DETECTION_WINDOW);

            // 3. 현재 누적 포트 개수 조회 (SCARD)
            Long distinctPorts = redisTemplate.opsForSet().size(key);

            // 4. 탐지 조건:
            // - 현재 개수가 임계치와 정확히 일치하고 (distinctPorts == threshold)
            // - 방금 새로운 포트가 추가되었을 때 (addedCount > 0)
            // -> 이렇게 해야 21번째, 22번째 포트가 들어올 때 중복 알림을 막을 수 있음
            if (distinctPorts != null && distinctPorts == threshold && addedCount > 0) {
                return srcIp;
            }
        } catch (Exception e) {
            log.error("Redis operation failed in PortScanDetector", e);
            // Redis 장애 시 시스템 전체가 멈추지 않도록 null 반환 (Fail-Open)
        }
        return null;
    }
}
