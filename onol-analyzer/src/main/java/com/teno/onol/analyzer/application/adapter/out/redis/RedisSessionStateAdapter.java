package com.teno.onol.analyzer.application.adapter.out.redis;

import com.teno.onol.analyzer.application.port.out.ManageSessionStatePort;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.connection.RedisStringCommands;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.types.Expiration;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.stereotype.Repository;

import java.time.Duration;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Repository
@RequiredArgsConstructor
public class RedisSessionStateAdapter implements ManageSessionStatePort {

    private final StringRedisTemplate redisTemplate;
    private static final String KEY_PREFIX = "flow:";
    private static final Duration SESSION_TTL = Duration.ofHours(1); // 1시간 만료

    @Override
    public String getSessionState(String flowKey) {
        return redisTemplate.opsForValue().get(KEY_PREFIX + flowKey);
    }

    // Bulk 조회 (MGET)
    @Override
    public Map<String, String> getSessionStates(List<String> flowKeys) {
        if (flowKeys.isEmpty()) return Collections.emptyMap();

        List<String> fullKeys = flowKeys.stream().map(k -> KEY_PREFIX + k).toList();
        List<String> values = redisTemplate.opsForValue().multiGet(fullKeys); // MGET (1회 호출)

        if (values == null) return Collections.emptyMap();

        Map<String, String> result = new HashMap<>();
        for (int i = 0; i < flowKeys.size(); i++) {
            String val = values.get(i);
            if (val != null) {
                result.put(flowKeys.get(i), val);
            }
        }
        return result;
    }

    @Override
    public void updateSessionState(String flowKey, String state) {
        // setIfAbsent 등을 쓸 수도 있지만, 상태 갱신은 덮어쓰기가 기본
        redisTemplate.opsForValue().set(KEY_PREFIX + flowKey, state, SESSION_TTL);
    }

    // Bulk 저장 (Pipelining + 표준 명령어 사용)
    @Override
    public void updateSessionStates(Map<String, String> updates) {
        if (updates.isEmpty()) return;

        redisTemplate.executePipelined((RedisCallback<Object>) connection -> {
            RedisSerializer<String> serializer = redisTemplate.getStringSerializer();

            for (Map.Entry<String, String> entry : updates.entrySet()) {
                byte[] key = serializer.serialize(KEY_PREFIX + entry.getKey());
                byte[] value = serializer.serialize(entry.getValue());
                // SET + EXPIRE
                connection.stringCommands().set(
                        key,
                        value,
                        Expiration.seconds(SESSION_TTL.getSeconds()),
                        RedisStringCommands.SetOption.upsert() // 덮어쓰기 (UPSERT)
                );
            }
            return null;
        });
    }

    @Override
    public void removeSessionState(String flowKey) {
        redisTemplate.delete(KEY_PREFIX + flowKey);
    }

    // Bulk 삭제 (Native DEL Command)
    @Override
    public void removeSessionStates(List<String> flowKeys) {
        if (flowKeys.isEmpty()) return;

        List<String> fullKeys = flowKeys.stream().map(k -> KEY_PREFIX + k).toList();

        // delete(Collection)은 Redis의 'DEL k1 k2 k3 ...' 명령어로 변환되어 전송됨 (매우 빠름)
        redisTemplate.delete(fullKeys);
    }
}
