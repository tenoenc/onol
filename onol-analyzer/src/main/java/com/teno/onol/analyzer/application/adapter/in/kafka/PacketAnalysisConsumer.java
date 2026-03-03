package com.teno.onol.analyzer.application.adapter.in.kafka;

import com.teno.onol.analyzer.application.port.in.RecordPacketUseCase;
import com.teno.onol.core.domain.PacketEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.stream.function.StreamBridge;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.support.MessageBuilder;

import java.util.List;
import java.util.function.Consumer;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class PacketAnalysisConsumer {

    private final RecordPacketUseCase recordPacketUseCase;
    private final StreamBridge streamBridge;

    // application.yml의 'processPacket-in-0'과 매핑됨
    @Bean
    public Consumer<List<PacketEvent>> processPacket() {
        return events -> {
            try {
                recordPacketUseCase.recordPackets(events);
                log.info("Received batch of {} packets from Kafka", events.size());
            } catch (Exception e) {
                log.error("Failed to save packet batch", e);
                sendToDlq(events, e.getMessage());
            }
        };
    }

    /**
     * 실패한 패킷 리스트를 DLQ 토픽으로 전송
     */
    private void sendToDlq(List<PacketEvent> events, String errorMessage) {
        try {
            // 실패 원인을 헤더에 담아서 전송
            streamBridge.send("sendToDlq-out-0",
                    MessageBuilder.withPayload(events)
                            .setHeader("error-msg", errorMessage) // 왜 실패했는지 기록
                            .setHeader("failed-at", System.currentTimeMillis())
                            .build()
            );
            log.info(">> Sent {} packets to DLQ (packet-dlq-topic)", events.size());
        } catch (Exception ex) {
            log.error("CRITICAL: Failed to send to DLQ! Data loss occurred.", ex);
        }
    }
}
