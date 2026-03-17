package com.teno.onol.analyzer.application.service;

import com.teno.onol.analyzer.application.port.out.ManageSessionStatePort;
import com.teno.onol.analyzer.application.port.out.ResolveGeoIpPort;
import com.teno.onol.analyzer.application.port.out.SavePacketLogPort;
import com.teno.onol.analyzer.domain.PacketLog;
import com.teno.onol.analyzer.domain.TcpSessionTracker;
import com.teno.onol.core.domain.PacketEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class PacketLogWorker {

    private final ManageSessionStatePort sessionStatePort;
    private final SavePacketLogPort savePacketLogPort;
    private final ResolveGeoIpPort resolveGeoIpPort;
    private final TcpSessionTracker tcpSessionTracker;

    /**
     * 패킷 필터링, 변환, DB 저장을 별도 스레드에서 수행
     */
    @Async("packetLogExecutor")
    public void filterAndSaveAsync(List<PacketEvent> events) {
        long start = System.currentTimeMillis();

        try {
            // 1. 스마트 필터링
            List<PacketLog> logsToSave = filterAndMapPackets(events);

            // 2. DB 저장
            if (!logsToSave.isEmpty()) {
                savePacketLogPort.saveAll(logsToSave);
            }

            long duration = System.currentTimeMillis() - start;

            // 3. 프로토콜별 상세 통계 집계
            int inputCount = events.size();
            int savedCount = logsToSave.size();
            double reductionRate = inputCount > 0 ? 100.0 - ((double) savedCount / inputCount * 100.0) : 0.0;

            // Input 통계 (PacketEvent는 String 프로토콜)
            long tcpInput = events.stream().filter(e -> "TCP".equalsIgnoreCase(e.protocol())).count();
            long udpInput = events.stream().filter(e -> "UDP".equalsIgnoreCase(e.protocol())).count();

            // Saved 통계 (PacketLog는 int 프로토콜: TCP=6, UDP=17)
            long tcpSaved = logsToSave.stream().filter(l -> l.getProtocol() == 6).count();
            long udpSaved = logsToSave.stream().filter(l -> l.getProtocol() == 17).count();

            // 4. 상세 로그 출력
            log.info("[Async] Batch: {} -> Saved: {} (TCP: {}/{} | UDP: {}/{}) | ↓{}% Reduced | Time: {}ms",
                    inputCount,
                    savedCount,
                    tcpSaved, tcpInput,
                    udpSaved, udpInput,
                    String.format("%.1f", reductionRate),
                    duration);
        } catch (Exception e) {
            log.error("Async Packet Save Failed", e);
        }
    }

    private List<PacketLog> filterAndMapPackets(List<PacketEvent> events) {
        List<String> flowKeys = events.stream()
                .filter(e -> "TCP".equalsIgnoreCase(e.protocol()) || "UDP".equalsIgnoreCase(e.protocol()))
                .map(tcpSessionTracker::generateFlowKey) // UDP도 IP:Port 쌍으로 키 생성 가능
                .toList();

        Map<String, Long> packetCounts = sessionStatePort.incrementPacketCounts(flowKeys);

        List<PacketLog> result = new ArrayList<>();
        int keyIndex = 0;

        for (PacketEvent event : events) {
            boolean shouldSave = false;
            boolean isTcp = "TCP".equalsIgnoreCase(event.protocol());
            boolean isUdp = "UDP".equalsIgnoreCase(event.protocol());

            if (isTcp || isUdp) {
                String key = flowKeys.get(keyIndex++);
                Long count = packetCounts.getOrDefault(key, 0L);

                if (isTcp) {
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
                    // UDP 필터링 로직
                    // QUIC는 제어 플래그가 없으므로 순수하게 카운트로만 판단
                    // DNS(53)나 NTP(123) 같은 저용량 프로토콜은 계속 저장해도 됨

                    // [규칙 4] DNS는 중요하니까 저장
                    if (event.dstPort() == 53 || event.srcPort() == 53) {
                        shouldSave = true;
                    }
                    // [규칙 5] 스트리밍 데이터 덩어리는 10개 이후 버림
                    else if (count <= 10) {
                        shouldSave = true;
                    }
                }
            } else {
                // ICMP 등 기타 프로토콜은 저장
                shouldSave = true;
            }

            if (shouldSave) {
                result.add(enrichAndMapToDomain(event));
            }
        }
        return result;
    }

    private PacketLog enrichAndMapToDomain(PacketEvent event) {
        String country = resolveGeoIpPort.resolveCountryCode(event.srcIp());
        if ("INT".equals(country) || country == null) {
            country = resolveGeoIpPort.resolveCountryCode(event.dstIp());
        }

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
