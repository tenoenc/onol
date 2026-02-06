package com.teno.onol.analyzer.application.port.out;

import java.time.Instant;

public interface RecordHeartbeatPort {
    void recordHeartbeat(Instant timestamp, String status);
}
