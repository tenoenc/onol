package com.teno.onol.collector.application.adapter.out.kafka;

import com.teno.onol.collector.application.port.out.SendPacketPort;
import com.teno.onol.core.domain.PacketEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.stream.function.StreamBridge;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class KafkaProducerAdapter implements SendPacketPort {

    private final StreamBridge streamBridge; // Spring Cloud Stream Kafka 전송기

    // Kafka Topic Binding Name (application.yml과 일치해야 함)
    private static final String BINDING_NAME = "packet-out-0";

    @Override
    public void sendPacket(PacketEvent event) {
        // 객체(event)를 그대로 보내면 NPE가 발생할 수 있으므로 Message로 감싸서 보냅니다.
        boolean sent = streamBridge.send(BINDING_NAME, MessageBuilder.withPayload(event).build());

        if (!sent) {
            log.warn("Failed to send packet to Kafka via binding: {}", BINDING_NAME);
        }
    }
}
