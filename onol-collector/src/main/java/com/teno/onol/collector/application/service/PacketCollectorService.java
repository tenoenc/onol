package com.teno.onol.collector.application.service;

import com.teno.onol.collector.application.port.in.CollectPacketUseCase;
import com.teno.onol.collector.application.port.out.SendPacketPort;
import com.teno.onol.core.domain.PacketEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class PacketCollectorService implements CollectPacketUseCase {

    private final SendPacketPort sendPacketPort;
    private final NoiseFilter noiseFilter;

    @Override
    public void collect(PacketEvent event) {
        try {
            // 1. Noise Filter Check
            if (noiseFilter.isNoise(event)) return;

            // 2. Send to Kafka
            sendPacketPort.sendPacket(event);
        } catch (Exception e) {
            log.error("Error processing packet event", e);
        }
    }
}
