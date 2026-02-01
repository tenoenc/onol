package com.teno.onol.collector.application.port.in;

import com.teno.onol.core.domain.PacketEvent;

public interface CollectPacketUseCase {
    void collect(PacketEvent event);
}
