package com.teno.onol.analyzer.application.service;

import com.teno.onol.analyzer.application.port.out.SendNotificationPort;
import com.teno.onol.analyzer.domain.ThreatDetectedEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class ThreatDetectedEventListener {

    private final List<SendNotificationPort> notificationPorts;

    @Async("taskExecutor")
    @EventListener
    public void handle(ThreatDetectedEvent event) {
        log.info("Event Received: Threat from {}. Broadcasting to {} channels.",
                event.attackerIp(), notificationPorts.size());

        // 등록된 모든 채널로 알림 발송
        notificationPorts.forEach(port -> port.sendNotification(event));
    }
}
