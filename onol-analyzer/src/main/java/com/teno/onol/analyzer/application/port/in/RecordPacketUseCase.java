package com.teno.onol.analyzer.application.port.in;

import com.teno.onol.core.domain.PacketEvent;

import java.util.List;

public interface RecordPacketUseCase {
    void recordPackets(List<PacketEvent> events);
}
