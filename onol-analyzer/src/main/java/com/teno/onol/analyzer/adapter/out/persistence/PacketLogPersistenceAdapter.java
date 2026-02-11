package com.teno.onol.analyzer.adapter.out.persistence;

import com.teno.onol.analyzer.application.port.out.SavePacketLogPort;
import com.teno.onol.analyzer.domain.PacketLog;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;

@Slf4j
@Repository
@RequiredArgsConstructor
public class PacketLogPersistenceAdapter implements SavePacketLogPort {

    private final JdbcTemplate jdbcTemplate;

    @Override
    public void saveAll(List<PacketLog> logs) {
        if (logs.isEmpty()) return;

        String sql = """
                INSERT INTO raw_packet_log
                (time, src_ip, dst_ip, src_port, dst_port, protocol,
                tcp_flags, payload_len, payload, country_code, domain_name)
                VALUES (?, ?::inet, ?::inet, ?, ?, ?, ?, ?, ?, ?, ?)
                """;

        jdbcTemplate.batchUpdate(sql, logs, logs.size(), (ps, log) -> {
            ps.setObject(1, log.getTime());
            ps.setString(2, log.getSrcIp());
            ps.setString(3, log.getDstIp());
            ps.setInt(4, log.getSrcPort());
            ps.setInt(5, log.getDstPort());
            ps.setInt(6, log.getProtocol());
            ps.setInt(7, log.getTcpFlags());
            ps.setInt(8, log.getPayloadLen());

//            ps.setBytes(9, log.getPayload());
            // 어차피 암호화된 데이터라 봐도 모름. SNI만 있으면 됨.
            ps.setBytes(9, null);

            ps.setString(10, log.getCountryCode());
            ps.setString(11, log.getDomainName());
        });

        log.debug("Saved {} packets to DB.", logs.size());
    }
}
