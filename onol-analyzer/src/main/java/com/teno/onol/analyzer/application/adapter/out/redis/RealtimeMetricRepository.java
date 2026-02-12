package com.teno.onol.analyzer.application.adapter.out.redis;

import com.teno.onol.analyzer.application.port.out.RecordRealtimeMetricPort;
import com.teno.onol.core.domain.PacketEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
@RequiredArgsConstructor
public class RealtimeMetricRepository implements RecordRealtimeMetricPort {

    private final StringRedisTemplate redisTemplate;

    @Override
    public void incrementMetrics(List<PacketEvent> events) {
        if (events.isEmpty()) return;

        // Pipelining: 네트워크 왕복은 1번으로 줄임
        redisTemplate.executePipelined((RedisCallback<Object>) connection -> {
            for (PacketEvent event : events) {
                // Key: traffic:speed:{timestamp_seconds}
                long epochSecond = event.timestamp().getEpochSecond();
                String key = "traffic:speed:" + epochSecond;

                // Expiration: 5분 (차트에 그려지고 나면 자동 삭제)
                byte[] keyBytes = key.getBytes();

                // PPS (Packet Per Second)
                connection.hashCommands().hIncrBy(keyBytes, "pps".getBytes(), 1);

                // BPS (Bytes Per Second) + payloadLen
                connection.hashCommands().hIncrBy(keyBytes, "bps".getBytes(), event.payloadLen());

                // TTL 설정 (매번 설정하면 비효율적일 수 있으나, 안전을 위해)
                connection.keyCommands().expire(keyBytes, 300);
            }
            return null;
        });
    }
}
