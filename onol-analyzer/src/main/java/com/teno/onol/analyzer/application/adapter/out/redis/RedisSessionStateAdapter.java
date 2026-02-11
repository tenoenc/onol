package com.teno.onol.analyzer.application.adapter.out.redis;

import com.teno.onol.analyzer.application.port.out.ManageSessionStatePort;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Repository;

import java.time.Duration;

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

    @Override
    public void updateSessionState(String flowKey, String state) {
        // setIfAbsent 등을 쓸 수도 있지만, 상태 갱신은 덮어쓰기가 기본
        redisTemplate.opsForValue().set(KEY_PREFIX + flowKey, state, SESSION_TTL);
    }

    @Override
    public void removeSessionState(String flowKey) {
        redisTemplate.delete(KEY_PREFIX + flowKey);
    }
}
