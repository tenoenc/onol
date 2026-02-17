package com.teno.onol.analyzer.application.adapter.out.notification;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.teno.onol.analyzer.application.port.out.SendNotificationPort;
import com.teno.onol.analyzer.domain.ThreatDetectedEvent;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

@Slf4j
@Component
public class SlackNotificationAdapter implements SendNotificationPort {

    @Value("${onol.notification.slack-webhook-url:}")
    private String webhookUrl;

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void sendNotification(ThreatDetectedEvent event) {
        if (webhookUrl == null || webhookUrl.isBlank()) {
//            log.warn("[Mock-Slack] (설정된 Webhook URL 없음) 위협 감지: {} ({}) - {}",
//                    event.attackerIp(), event.threatType(), event.message());
            return;
        }

        try {
            Map<String, String> payload = Map.of(
                    "text", String.format("""
                    **Threat Detected!**
                    - **IP**: `%s`
                    - **Type**: `%s`
                    - **Message**: %s
                    """, event.attackerIp(), event.threatType(), event.message())
            );

            String jsonBody = objectMapper.writeValueAsString(payload);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(webhookUrl))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                    .build();

            httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                    .thenAccept(res -> {
                        if (res.statusCode() != 200) {
                            log.error("Failed to send Slack notification. Status: {}", res.statusCode());
                        }
                    });

        } catch (Exception e) {
            log.error("Error sending notification", e);
        }
    }
}
