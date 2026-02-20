package com.teno.onol.analyzer.application.service;

import com.teno.onol.analyzer.application.port.out.SendNotificationPort;
import com.teno.onol.analyzer.domain.ThreatDetectedEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.mockito.Mockito.*;

public class ThreatDetectedEventListenerTest {

    private ThreatDetectedEventListener listener;
    private SendNotificationPort slackMock;
    private SendNotificationPort discordMock;

    @BeforeEach
    void setUp() {
        // Mock 객체 생성
        slackMock = mock(SendNotificationPort.class);
        discordMock = mock(SendNotificationPort.class);

        // 리스너에 Mock 리스트 주입 (Slack, Discord 두 개가 있다고 가정)
        listener = new ThreatDetectedEventListener(List.of(slackMock, discordMock));
    }

    @Test
    @DisplayName("위협 감지 이벤트 수신 시 등록된 모든 채널로 알림을 발송해야 한다")
    void should_BroadcastNotification_To_AllChannels() {
        // given
        ThreatDetectedEvent event = ThreatDetectedEvent.builder()
                .attackerIp("1.1.1.1")
                .threatType("PORT_SC")
                .message("Scanning...")
                .detectedAt(Instant.now())
                .build();

        // when
        listener.handle(event);

        // then
        // 두 어댑터 모두 호출되었는지 확인
        verify(slackMock, times(1)).sendNotification(event);
        verify(discordMock, times(1)).sendNotification(event);
    }
}
