package com.teno.onol.analyzer.domain;

import lombok.Builder;

import java.time.Instant;

@Builder
public record ThreatDetectedEvent(
        String attackerIp,
        String threatType, // PORT_SCAN ...
        String message,
        Instant detectedAt
) { }