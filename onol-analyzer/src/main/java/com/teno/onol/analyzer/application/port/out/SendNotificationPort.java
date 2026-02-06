package com.teno.onol.analyzer.application.port.out;

import com.teno.onol.analyzer.domain.ThreatDetectedEvent;

public interface SendNotificationPort {
    void sendNotification(ThreatDetectedEvent event);
}
