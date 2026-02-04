package com.teno.onol.collector.application.service;

import com.teno.onol.collector.application.port.out.SendPacketPort;
import com.teno.onol.core.domain.PacketEvent;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class PacketCollectorServiceTest {

    @Mock
    private SendPacketPort sendPacketPort;

    @Mock
    private NoiseFilter noiseFilter;

    @InjectMocks
    private PacketCollectorService packetCollectorService;

    @Test
    @DisplayName("노이즈로 판별된 패킷은 전송되지 않아야 한다")
    void should_DropPacket_When_NoiseDetected() {
        // given
        PacketEvent noisePacket = PacketEvent.builder()
                .timestamp(Instant.now())
                .srcIp("1.1.1.1").srcPort(80)
                .dstIp("2.2.2.2").srcPort(1000)
                .protocol("TCP")
                .build();
        when(noiseFilter.isNoise(noisePacket)).thenReturn(true);

        // when
        packetCollectorService.collect(noisePacket);

        // then
        verify(sendPacketPort, never()).sendPacket(any());
    }

    @Test
    @DisplayName("정상 패킷은 SendPort를 통해 전송되어야 한다")
    void should_SendPacket_When_NormalPacketReceived() {
        // given
        PacketEvent normalPacket = PacketEvent.builder()
                .timestamp(Instant.now())
                .srcIp("1.1.1.1").srcPort(80)
                .dstIp("2.2.2.2").srcPort(1000)
                .protocol("TCP")
                .build();
        when(noiseFilter.isNoise(normalPacket)).thenReturn(false); // 정상 패킷 가정

        // when
        packetCollectorService.collect(normalPacket);

        // then
        verify(sendPacketPort, times(1)).sendPacket(normalPacket); // 전송 호출 확인
    }

}
