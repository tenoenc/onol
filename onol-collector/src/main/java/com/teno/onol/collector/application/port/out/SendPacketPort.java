package com.teno.onol.collector.application.port.out;

import com.teno.onol.core.domain.PacketEvent;

public interface SendPacketPort {
    void sendPacket(PacketEvent event);
}
