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
import java.util.*;

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

        // 4. 스마트 필터링 및 저장
        List<PacketLog> logsToSave = filterAndMapPackets(events);

        // 5. 선별된 로그만 DB 저장
        if (!logsToSave.isEmpty()) {
            savePacketLogPort.saveAll(logsToSave);
        }
    }

    private List<PacketLog> filterAndMapPackets(List<PacketEvent> events) {
        // A. 카운트 조회를 위한 키 생성 (TCP만 대상)
        List<String> tcpKeys = events.stream()
                .filter(e -> "TCP".equalsIgnoreCase(e.protocol()))
                .map(tcpSessionTracker::generateFlowKey)
                .toList();

        // B. Redis Bulk Increment (한 번에 카운트 증가 및 조회)
        Map<String, Long> packetCounts = sessionStatePort.incrementPacketCounts(tcpKeys);

        List<PacketLog> result = new ArrayList<>();
        int tcpIndex = 0;

        for (PacketEvent event : events) {
            boolean shouldSave = false;

            if ("TCP".equalsIgnoreCase(event.protocol())) {
                String key = tcpKeys.get(tcpIndex++);
                Long count = packetCounts.getOrDefault(key, 0L);
                int flags = event.tcpFlags();

                // [규칙 1] 제어 패킷(SYN, FIN, RST)은 무조건 저장
                if ((flags & (PacketEvent.FLAG_SYN | PacketEvent.FLAG_FIN | PacketEvent.FLAG_RST)) != 0) {
                    shouldSave = true;
                }

                // [규칙 2] 초반 10개 패킷(Head)은 문맥 파악을 위해 저장 (HTTP 헤더 등 포함)
                else if (count <= 10) {
                    shouldSave = true;
                }
                // [규칙 3] 그 외(Tail) 데이터 덩어리는 과감히 버림 (단, 메트릭에는 이미 반영됨)
            } else {
                // UDP/ICMP 등은 일단 다 저장 (양이 상대적으로 적음)
                // 필요시 여기도 필터링 추가 기능
                shouldSave = true;
            }

            if (shouldSave) {
                // GeoIP Enrichment
                result.add(enrichAndMapToDomain(event));
            }
        }
        return result;
    }

    private void trackSessions(List<PacketEvent> events) {
        // 1. TCP 패킷만 골라서 Flow Key 미리 생성
        List<PacketEvent> tcpEvents = events.stream()
                .filter(e -> "TCP".equalsIgnoreCase(e.protocol()))
                .toList();
        if (tcpEvents.isEmpty()) return;

        List<String> flowKeys = tcpEvents.stream()
                .map(tcpSessionTracker::generateFlowKey)
                .toList();

        // 2. Redis 한 번만 갔다 오기
        Map<String, String> currentStates = sessionStatePort.getSessionStates(flowKeys);
        Map<String, String> updates = new HashMap<>();

        // 3. 메모리에서 상태 계산 (매우 빠름)
        for (int i = 0; i < tcpEvents.size(); i++) {
            PacketEvent event = tcpEvents.get(i);
            String key = flowKeys.get(i);

            // 루프 돌면서 상태가 변할 수 있으므로 updates 맵을 우선 확인 (Batch 내 순서 보장)
            String currentState = updates.getOrDefault(key, currentStates.get(key));
            String nextState = tcpSessionTracker.determineNextState(currentState, event);

            if (!nextState.equals(currentState)) {
                updates.put(key, nextState);
                if ("ESTABLISHED".equals(nextState) && !"ESTABLISHED".equals(currentState)) {
                    log.debug("Conn Est: {}", key);
                }
            }
        }

        // 4. 변경된 것만 모아서 한 방에 저장
        sessionStatePort.updateSessionStates(updates);
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
