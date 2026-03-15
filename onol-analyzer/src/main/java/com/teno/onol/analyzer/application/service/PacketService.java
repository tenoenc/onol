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

    private final RecordRealtimeMetricPort recordRealtimeMetricPort;
    private final PortScanDetector portScanDetector;
    private final TcpSessionTracker tcpSessionTracker;
    private final ManageSessionStatePort sessionStatePort;
    private final ApplicationEventPublisher eventPublisher;
    private final PacketLogWorker packetLogWorker;

    @Override
    @Transactional
    public void recordPackets(List<PacketEvent> events) {
        // 1. 실시간 메트릭 집계 (Redis)
        recordRealtimeMetricPort.incrementMetrics(events);

        // 2. 위협 탐지 (Port Scan)
        // 보안 알림은 즉시 나가야 함 (동기)
        detectThreats(events);

        // 3. 세션 추적
        // 상태 전이(SYN->EST)는 순서가 중요함 (동기)
        trackSessions(events);

        // 4. 스마트 필터링 및 저장
        // 메인 스레드는 여기서 블로킹되지 않고 즉시 리턴됨 (비동기)
        packetLogWorker.filterAndSaveAsync(events);
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
}
