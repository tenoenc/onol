package com.teno.onol.analyzer.adapter.out.redis;

import com.teno.onol.analyzer.application.adapter.out.redis.RedisSessionStateAdapter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.data.redis.DataRedisTest;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.core.StringRedisTemplate;

import static org.assertj.core.api.Assertions.assertThat;

@DataRedisTest
@Import(RedisSessionStateAdapter.class)
public class RedisSessionStateAdapterTest {

    @Autowired
    private RedisSessionStateAdapter adapter;

    @Autowired
    private StringRedisTemplate redisTemplate;

    @Test
    @DisplayName("세션 상태를 저장하고 조회할 수 있어야 한다")
    void should_SaveAndGet_SessionState() {
        // given
        String flowKey = "1.1.1.1:10->2.2.2.2:20";
        String state = "SYN_SENT";

        // when
        adapter.updateSessionState(flowKey, state);

        // then
        // 1. Adapter를 통해 조회
        assertThat(adapter.getSessionState(flowKey)).isEqualTo(state);

        // 2. 실제 Redis Key 확인 (Prefix 검증)
        String realKey = "flow:" + flowKey;
        assertThat(redisTemplate.opsForValue().get(realKey)).isEqualTo(state);
    }

    @Test
    @DisplayName("세션 상태를 삭제하면 조회되지 않아야 한다")
    void should_Remove_SessionState() {
        // given
        String flowKey = "delete:test";
        adapter.updateSessionState(flowKey, "ESTABLISHED");

        // when
        adapter.removeSessionState(flowKey);

        // then
        assertThat(adapter.getSessionState(flowKey)).isNull();
    }
}
