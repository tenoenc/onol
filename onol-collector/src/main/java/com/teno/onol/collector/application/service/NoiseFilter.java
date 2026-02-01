package com.teno.onol.collector.application.service;

import com.teno.onol.core.domain.PacketEvent;
import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * 수집된 패킷 중 저장할 가치가 없는 노이즈를 걸러내는 필터
 * 피드백 루프 방지 및 루프백 제거
 */
@Component
public class NoiseFilter {

    // 차단할 인프라 포트: Kafka(9092), TimescaleDB(5432), Redis(6379), Zookeeper(2181)
    private static final Set<Integer> IGNORED_PORTS = Set.of(9092, 5432, 6379, 2181);

    private static final String LOOPBACK_IPV4 = "127.0.0.1";
    private static final String LOOPBACK_IPV6 = "0:0:0:0:0:0:0:1"; // ::1
    private static final String LOCALHOST = "localhost";

    public boolean isNoise(PacketEvent packet) {
        // 1. Loopback Filter
        if (isLoopback(packet.srcIp()) || isLoopback(packet.dstIp())) {
            return true;
        }

        // 2. Infrastructure Traffic Filter (Feedback Loop Prevention)
        if (IGNORED_PORTS.contains(packet.srcPort()) || IGNORED_PORTS.contains(packet.dstPort())) {
            return true;
        }

        return false;
    }

    private boolean isLoopback(String ip) {
        return LOOPBACK_IPV4.equals(ip) || LOOPBACK_IPV6.equals(ip) || LOCALHOST.equalsIgnoreCase(ip);
    }
}
