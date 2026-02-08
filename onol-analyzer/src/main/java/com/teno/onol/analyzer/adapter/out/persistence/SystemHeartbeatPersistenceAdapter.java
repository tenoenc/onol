package com.teno.onol.analyzer.adapter.out.persistence;

import com.teno.onol.analyzer.application.port.out.RecordHeartbeatPort;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;

@Slf4j
@Repository
@RequiredArgsConstructor
public class SystemHeartbeatPersistenceAdapter implements RecordHeartbeatPort {

    private final JdbcTemplate jdbcTemplate;

    @Override
    public void recordHeartbeat(Instant timestamp, String status) {

        String sql = """
            INSERT INTO system_heartbeat (last_alive_time, app_version, status)
            VALUES (?, 'v1.0', ?)
        """;

        try {
            jdbcTemplate.update(sql, Timestamp.from(timestamp), status);
        } catch (Exception e) {
            log.error("Failed to record heartbeat", e);
        }
    }
}
