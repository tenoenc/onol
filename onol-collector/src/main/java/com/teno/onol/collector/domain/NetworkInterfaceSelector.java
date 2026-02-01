package com.teno.onol.collector.domain;

import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.PcapNetworkInterface;
import org.springframework.stereotype.Component;

import java.util.List;

@Slf4j
@Component
public class NetworkInterfaceSelector {

    public PcapNetworkInterface selectBestInterface(List<PcapNetworkInterface> allDevs) {
        if (allDevs == null || allDevs.isEmpty()) return null;

        for (PcapNetworkInterface nif : allDevs) {
            // 1. 루프백 제외
            if (nif.isLoopBack()) continue;

            // 2. Down 상태 제외
            if (!nif.isUp()) continue;

            // 3. IP 주소가 없으면(연결 안 됨) 제외
            if (nif.getAddresses().isEmpty()) continue;

            // 4. 특정 이름 필터링 (bridge, docker, ...)
            if (isVirtualInterface(nif.getName())) continue;

            log.info("Found best network interface: {} ({})", nif.getName(), nif.getDescription());
            return nif; // 조건에 맞는 첫 번째 발견 시 리턴
        }
        return null;
    }

    private boolean isVirtualInterface(String name) {
        // 도커, 브리지, 가상 이더넷 등은 실제 외부 트래픽 수집과 다를 수 있어 제외
        String lower = name.toLowerCase();
        return lower.contains("docker") ||
                lower.contains("br-") ||
                lower.contains("veth") ||
                lower.contains("tun") ||
                lower.contains("tap");
    }
}
