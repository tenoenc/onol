package com.teno.onol.analyzer.application.port.out;

import com.teno.onol.analyzer.domain.PacketLog;

import java.util.List;

public interface SavePacketLogPort {
    void saveAll(List<PacketLog> logs);
}
