package com.teno.onol.analyzer.adapter.in.kafka;

import com.teno.onol.analyzer.application.adapter.in.kafka.PacketAnalysisConsumer;
import com.teno.onol.analyzer.application.port.in.RecordPacketUseCase;
import com.teno.onol.core.domain.PacketEvent;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cloud.stream.function.StreamBridge;
import org.springframework.messaging.Message;

import java.time.Instant;
import java.util.List;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.anyString;

@ExtendWith(MockitoExtension.class)
public class PacketAnalyzerConsumerTest {

    @Mock
    private RecordPacketUseCase recordPacketUseCase;

    @Mock
    private StreamBridge streamBridge;

    @InjectMocks
    private PacketAnalysisConsumer packetAnalysisConsumer; // 테스트 대상

    @Test
    @DisplayName("패킷 배치를 받으면 UseCase를 호출해야 한다")
    void should_CallUseCase_When_BatchReceived() {
        // given
        Instant ts1 = Instant.now();
        PacketEvent event1 = PacketEvent.builder()
                .timestamp(ts1)
                .srcIp("1.1.1.1")
                .dstIp("2.2.2.2")
                .srcPort(10)
                .dstPort(20)
                .protocol("TCP")
                .build();
        Instant ts = Instant.now();
        PacketEvent event2 = PacketEvent.builder()
                .timestamp(ts)
                .srcIp("3.3.3.3")
                .dstIp("4.4.4.4")
                .srcPort(30)
                .dstPort(40)
                .protocol("UDP")
                .build();
        List<PacketEvent> batch = List.of(event1, event2);

        // when
        packetAnalysisConsumer.processPacket().accept(batch);

        // then
        verify(recordPacketUseCase, times(1)).recordPackets(anyList());
        verify(streamBridge, never()).send(anyString(), any(Message.class));
    }

    @Test
    @DisplayName("UseCase 실행 중 에러 발생 시 DLQ로 전송해야 한다")
    void should_SendToDLQ_When_UseCaseFails() {
        // given
        Instant ts = Instant.now();
        PacketEvent event = PacketEvent.builder()
                .timestamp(ts)
                .srcIp("1.1.1.1")
                .dstIp("2.2.2.2")
                .srcPort(10)
                .dstPort(20)
                .protocol("TCP")
                .build();
        List<PacketEvent> batch = List.of(event);

        // Mock: UseCase가 예외를 던짐
        doThrow(new RuntimeException("Business Logic Error"))
                .when(recordPacketUseCase).recordPackets(anyList());

        // when
        packetAnalysisConsumer.processPacket().accept(batch);

        // then
        verify(recordPacketUseCase, times(1)).recordPackets(anyList());
        verify(streamBridge, times(1)).send(
                eq("sendToDlq-out-0"),
                any(Message.class)
        );
    }
}
