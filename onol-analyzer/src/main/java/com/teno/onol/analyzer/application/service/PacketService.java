package com.teno.onol.analyzer.application.service;

import com.teno.onol.analyzer.application.port.in.RecordPacketUseCase;
import com.teno.onol.analyzer.application.port.out.ManageSessionStatePort;
import com.teno.onol.analyzer.application.port.out.RecordRealtimeMetricPort;
import com.teno.onol.analyzer.application.port.out.ResolveGeoIpPort;
import com.teno.onol.analyzer.application.port.out.SavePacketLogPort;
import com.teno.onol.analyzer.domain.PacketLog;
import com.teno.onol.analyzer.domain.PortScanDetector;
import com.teno.onol.analyzer.domain.TcpSessionTracker;
import com.teno.onol.analyzer.domain.ThreatDetectedEvent;
import com.teno.onol.core.domain.PacketEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class PacketService implements RecordPacketUseCase {

    private final SavePacketLogPort savePacketLogPort;
    private final ResolveGeoIpPort resolveGeoIpPort;
    private final RecordRealtimeMetricPort recordRealtimeMetricPort;
    private final PortScanDetector portScanDetector;
    private final TcpSessionTracker tcpSessionTracker;
    private final ManageSessionStatePort sessionStatePort;
    private final ApplicationEventPublisher eventPublisher;

    @Override
    @Transactional
    public void recordPackets(List<PacketEvent> events) {
        // 1. 실시간 메트릭 집계 (Redis)
        recordRealtimeMetricPort.incrementMetrics(events);

        // 2. 위협 탐지 (Port Scan)
        detectThreats(events);

        // 3. 세션 추적
        trackSessions(events);

        // 4. GeoIP Enrichment & DB Save
        List<PacketLog> logs = events.stream()
                .map(this::enrichAndMapToDomain)
                .toList();

        savePacketLogPort.saveAll(logs);
    }

    private void trackSessions(List<PacketEvent> events) {
        for (PacketEvent event : events) {
            if ("TCP".equalsIgnoreCase(event.protocol())) {
                // 1. 키 생성
                String key = tcpSessionTracker.generateFlowKey(event);

                // 2. 현재 상태 조회
                String currentState = sessionStatePort.getSessionState(key);

                // 3. 다음 상태 계산
                String nextState = tcpSessionTracker.determineNextState(currentState, event);

                // 4. 상태 저장/삭제
                if ("CLOSED".equals(nextState)) {
                    sessionStatePort.removeSessionState(key);
                } else if (!nextState.equals(currentState)) {
                    // 상태가 변했을 때만 갱신
                    sessionStatePort.updateSessionState(key, nextState);
                }

                // 세션이 막 성립되었거나 종료되었을 때 로그 남기기
                if ("ESTABLISHED".equals(nextState)) {
                    log.debug("Connection Established. {} -> {}", event.srcIp(), event.dstIp());
                }
            }
        }
    }

    private void detectThreats(List<PacketEvent> events) {
        Set<String> attackers = portScanDetector.detectScanners(events);

        for (String attackerIp : attackers) {
            log.warn("PORT SCAN DETECTED! Attacker: {}", attackerIp);

            eventPublisher.publishEvent(new ThreatDetectedEvent(
                    attackerIp,
                    "PORT_SCAN",
                    "Detected vertical port scanning behavior (Threshold exceeded)",
                    Instant.now()
            ));
        }
    }

    private PacketLog enrichAndMapToDomain(PacketEvent event) {
        // 1. GeoIP Enrichment
        String country = resolveGeoIpPort.resolveCountryCode(event.srcIp());
        if ("INT".equals(country) || country == null) {
            country = resolveGeoIpPort.resolveCountryCode(event.dstIp());
        }

        // 2. Map to Domain
        return PacketLog.builder()
                .time(event.timestamp().atZone(ZoneId.of("UTC")).toOffsetDateTime())
                .srcIp(event.srcIp())
                .dstIp(event.dstIp())
                .srcPort(event.srcPort())
                .dstPort(event.dstPort())
                .protocol("TCP".equalsIgnoreCase(event.protocol()) ? 6 :
                        "UDP".equalsIgnoreCase(event.protocol()) ? 17 : 0)
                .tcpFlags(event.tcpFlags())
                .payloadLen(event.payloadLen())
                .payload(event.payload())
                .domainName(event.domainName())
                .countryCode(country)
                .build();
    }


}
