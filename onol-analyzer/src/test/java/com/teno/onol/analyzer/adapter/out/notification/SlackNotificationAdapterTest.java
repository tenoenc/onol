package com.teno.onol.analyzer.adapter.out.notification;

import com.teno.onol.analyzer.application.adapter.out.notification.SlackNotificationAdapter;
import com.teno.onol.analyzer.domain.ThreatDetectedEvent;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class SlackNotificationAdapterTest {

    @Test
    @DisplayName("Webhook URL이 설정되지 않아도 에러가 발생하지 않아야 한다 (Fail-Safe)")
    void should_NotThrowException_When_UrlIsMissing() {
        // given
        SlackNotificationAdapter adapter = new SlackNotificationAdapter();
        // URL을 주입하지 않음 (null 상태)

        ThreatDetectedEvent event = new ThreatDetectedEvent(
                "1.2.3.4", "TEST", "Message", Instant.now()
        );

        // when & then
        // 로그만 찍고 넘어가야 함
        assertDoesNotThrow(() -> adapter.sendNotification(event));
    }
}