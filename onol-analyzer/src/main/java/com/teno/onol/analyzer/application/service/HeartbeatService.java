package com.teno.onol.analyzer.application.service;

import com.teno.onol.analyzer.application.port.out.RecordHeartbeatPort;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Slf4j
@Service
@RequiredArgsConstructor
public class HeartbeatService {

    private final RecordHeartbeatPort recordHeartbeatPort;

    // 1분마다 실행
    @Scheduled(fixedRate = 60000)
    public void beat() {
        recordHeartbeatPort.recordHeartbeat(Instant.now(), "ALIVE");
    }
}
