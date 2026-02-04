package com.teno.onol.collector.application.adapter.in.file;

import com.teno.onol.collector.application.port.in.CollectPacketUseCase;
import com.teno.onol.core.domain.PacketEvent;
import com.teno.onol.core.util.PacketUtils;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.io.EOFException;
import java.io.File;
import java.time.Instant;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;

@Slf4j
@Component
@Profile("test")
@RequiredArgsConstructor
public class FileReplayAdapter {

    private final CollectPacketUseCase collectPacketUseCase;

    @Value("${onol.collector.replay-file-path:src/test/resources/sample.pcap}")
    private String pcapFilePath;

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private volatile boolean running = false;

    @PostConstruct
    public void start(Consumer<PacketEvent> eventConsumer) {
        if (running) {
            log.warn("Replay is already running.");
            return;
        }

        File file = new File(pcapFilePath);
        if (!file.exists()) {
            log.warn("PCAP file not found at: {}. Replay skipped.", pcapFilePath);
            return;
        }

        running = true;
        // 메인 스레드 블로킹 방지
        executor.submit(this::replay);
    }

    private void replay() {
        PcapHandle handle = null;
        try {
            handle = Pcaps.openOffline(pcapFilePath);
            log.info("Starting PCAP Replay from: {}", pcapFilePath);

            long firstPacketTime = -1;
            long firstSystemTime = -1;

            while (running) {
                Packet packet;
                try {
                    packet = handle.getNextPacketEx();
                } catch (EOFException e) {
                    log.info("End of PCAP file reached.");
                    break;
                } catch (TimeoutException e) {
                    continue;
                }

                long currentPacketTime = handle.getTimestamp().getTime();

                // 첫 패킷 기준 시간 동기화
                if (firstPacketTime == -1) {
                    firstPacketTime = currentPacketTime;
                    firstSystemTime = System.currentTimeMillis();
                }

                // (패킷 간 시간 차이) - (시스템 경과 시간) = 기다려야 할 시간
                long timePassesInPacket = currentPacketTime - firstPacketTime;
                long timePassedInSystem = System.currentTimeMillis() - firstSystemTime;
                long sleepNeeded = timePassesInPacket - timePassedInSystem;

                if (sleepNeeded > 0) {
                    try {
                        Thread.sleep(sleepNeeded);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }

                PacketEvent event = PacketUtils.toEvent(packet, Instant.ofEpochMilli(currentPacketTime));

                // Consumer에게 전달 (Kafka 전송 등)
                collectPacketUseCase.collect(event);
            }
        } catch (Exception e) {
            log.error("Failed to run PCAP replay", e);
        } finally {
            if (handle != null) handle.close();
            running = false;
        }
    }

    @PreDestroy
    public void stop() {
        this.running = false;
        executor.shutdownNow();
    }
}
