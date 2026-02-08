package com.teno.onol.analyzer.application.service;

import com.teno.onol.analyzer.application.port.out.RecordHeartbeatPort;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class HeartbeatServiceTest {

    @Mock
    private RecordHeartbeatPort recordHeartbeatPort;

    @InjectMocks
    private HeartbeatService heartbeatService;

    @Test
    @DisplayName("비트(beat) 메서드가 호출되면 포트를 통해 ALIVE 상태를 기록해야 한다")
    void should_RecordAliveStatus_When_BeatCalled() {
        // when
        heartbeatService.beat();

        // then
        // 1. recordHeartbeat가 1번 호출되었는지 검증
        // 2. 상태값이 "ALIVE"인지 검증
        verify(recordHeartbeatPort, times(1))
                .recordHeartbeat(any(Instant.class), eq("ALIVE"));
    }
}
