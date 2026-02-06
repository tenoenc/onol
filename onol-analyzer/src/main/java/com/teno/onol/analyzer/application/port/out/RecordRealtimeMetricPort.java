package com.teno.onol.analyzer.application.port.out;

import com.teno.onol.core.domain.PacketEvent;

import java.util.List;

public interface RecordRealtimeMetricPort {
    void incrementMetrics(List<PacketEvent> events);
}
