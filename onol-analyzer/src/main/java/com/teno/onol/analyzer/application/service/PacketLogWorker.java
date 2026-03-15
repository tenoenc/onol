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
        try {
            // 1. 스마트 필터링
            List<PacketLog> logsToSave = filterAndMapPackets(events);

            // 2. DB 저장
            if (!logsToSave.isEmpty()) {
                savePacketLogPort.saveAll(logsToSave);
            }
        } catch (Exception e) {
            log.error("Async Packet Save Failed", e);
        }
    }

    private List<PacketLog> filterAndMapPackets(List<PacketEvent> events) {
        List<String> tcpKeys = events.stream()
                .filter(e -> "TCP".equalsIgnoreCase(e.protocol()))
                .map(tcpSessionTracker::generateFlowKey)
                .toList();

        Map<String, Long> packetCounts = sessionStatePort.incrementPacketCounts(tcpKeys);

        List<PacketLog> result = new ArrayList<>();
        int tcpIndex = 0;

        for (PacketEvent event : events) {
            boolean shouldSave = false;

            if ("TCP".equalsIgnoreCase(event.protocol())) {
                String key = tcpKeys.get(tcpIndex++);
                Long count = packetCounts.getOrDefault(key, 0L);
                int flags = event.tcpFlags();

                if ((flags & (PacketEvent.FLAG_SYN | PacketEvent.FLAG_FIN | PacketEvent.FLAG_RST)) != 0) {
                    shouldSave = true;
                }

                else if (count <= 10) {
                    shouldSave = true;
                }
            } else {
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
