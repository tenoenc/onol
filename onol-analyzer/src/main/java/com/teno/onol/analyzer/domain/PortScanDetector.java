package com.teno.onol.analyzer.domain;

import com.teno.onol.core.domain.PacketEvent;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.*;
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

        // 1. TCP/UDP만 필터링
        List<PacketEvent> candidates = packets.stream()
                .filter(p -> "TCP".equalsIgnoreCase(p.protocol()) || "UDP".equalsIgnoreCase(p.protocol()))
                .filter(p -> p.srcPort() != 53)
                .toList();

        if (candidates.isEmpty()) return Set.of();

        // 2. Redis Pipelining 실행 (비동기 명령 전송)
        List<Object> pipelineResults = redisTemplate.executePipelined((RedisCallback<Object>) connection -> {
            RedisSerializer<String> serializer = redisTemplate.getStringSerializer();

            for (PacketEvent event : candidates) {
                byte[] key = serializer.serialize(KEY_PREFIX + event.srcIp());
                byte[] port = serializer.serialize(String.valueOf(event.dstPort()));

                connection.sAdd(key, port); // 1. 추가
                connection.expire(key, DETECTION_WINDOW.getSeconds()); // 2. 연장
                connection.sCard(key); // 3. 개수 조회 (이 결과가 필요함)
            }

            return null;
        });

        // 3. 결과 분석 (Pipelining 결과는 순서대로 리스트에 담겨 옴)
        Set<String> attackers = new HashSet<>();
        int index = 0;

        for (PacketEvent event : candidates) {
            // 명령 3개를 보냈으니 결과도 3개씩 끊어서 읽어야 함
            // index: SADD 결과
            // index+1: EXPIRE 결과
            Object scardResult = pipelineResults.get(index + 2);// SCARD 결과
            Object saddResult = pipelineResults.get(index); // SADD 결과

            if (scardResult instanceof Long distinctPorts && saddResult instanceof Long addedCount) {
                if (distinctPorts == threshold && addedCount > 0) {
                    attackers.add(event.srcIp());
                }
            }
            index += 3; // 다음 패킷 결과로 이동
        }
        return attackers;
    }
}
