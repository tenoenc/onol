package com.teno.onol.analyzer.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.Executor;
import java.util.concurrent.ThreadPoolExecutor;

@Configuration
@EnableAsync
public class AsyncConfig {

    // 알림용 (가벼운 작업)
    @Bean(name = "taskExecutor")
    public Executor taskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(5); // 평소 대기 스레드
        executor.setMaxPoolSize(10); // 최대 스레드 (알림 폭주 시)
        executor.setQueueCapacity(100); // 대기열 크기
        executor.setThreadNamePrefix("Async-Notifier-");
        executor.initialize();
        return executor;
    }

    // 패킷 로그 저장용 (무거운 작업, 대용량 큐)
    @Bean(name = "packetLogExecutor")
    public Executor packetLogExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();

        executor.setCorePoolSize(4);
        executor.setMaxPoolSize(8);

        // 대기열: Kafka에서 가져온 패킷들이 DB 저장을 기다리는 곳
        // 5000개 배치 * 100개 = 약 50만 개 패킷 버퍼링 가능
        executor.setQueueCapacity(100);

        executor.setThreadNamePrefix("Packet-Log-Worker");

        // 거부 정책
        // 큐가 꽉 차면(DB가 너무 느리면), 메인 스레드(Kafka Consumer)가 직접 저장하게 함.
        // -> 이렇게 하면 Kafka 소비 속도가 자연스럽게 조절됨 (Backpressure)
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());

        executor.initialize();
        return executor;
    }
}
