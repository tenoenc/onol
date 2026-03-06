package com.teno.onol.analyzer.adapter.out.redis;

import com.teno.onol.analyzer.application.adapter.out.redis.RedisSessionStateAdapter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.data.redis.DataRedisTest;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.util.List;
import java.util.Map;

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

    @Test
    @DisplayName("Bulk Update: 여러 세션 상태를 Pipelining으로 한 번에 저장하고 조회해야 한다")
    void should_UpdateAndGet_BulkSessionStates() {
        // given
        String key1 = "1.1.1.1:10->2.2.2.2:20";
        String key2 = "3.3.3.3:30->4.4.4.4:40";
        Map<String, String> updates = Map.of(
                key1, "SYN_SENT",
                key2, "ESTABLISHED"
        );

        // when
        adapter.updateSessionStates(updates);

        // then
        // 1. Adapter의 Bulk Get으로 조회 검증
        Map<String, String> results = adapter.getSessionStates(List.of(key1, key2, "unknown:key"));

        assertThat(results).hasSize(2);
        assertThat(results.get(key1)).isEqualTo("SYN_SENT");
        assertThat(results.get(key2)).isEqualTo("ESTABLISHED");

        // 2. 실제 Redis에 저장된 키 확인 (Prefix 검증)
        assertThat(redisTemplate.hasKey("flow:" + key1)).isTrue();
    }

    @Test
    @DisplayName("Bulk Delete: 여러 세션 상태를 한 번의 명령으로 삭제해야 한다")
    void should_Remove_BulkSessionStates() {
        // given
        String key1 = "del:1";
        String key2 = "del:2";
        String key3 = "keep:3"; // 삭제하지 않을 키

        // 데이터 미리 저장
        adapter.updateSessionStates(Map.of(
                key1, "STATE1",
                key2, "STATE2",
                key3, "STATE3"
        ));

        // when (key1, key2만 삭제)
        adapter.removeSessionStates(List.of(key1, key2));

        // then
        Map<String, String> remaining = adapter.getSessionStates(List.of(key1, key2, key3));

        // key1, key2는 삭제되어 없어야 함
        assertThat(remaining.get(key1)).isNull();
        assertThat(remaining.get(key2)).isNull();

        // key3는 남아있어야 함
        assertThat(remaining.get(key3)).isEqualTo("STATE3");
    }
}
