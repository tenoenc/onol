package com.teno.onol.analyzer.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.Executor;

@Configuration
@EnableAsync
public class AsyncConfig {

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
}
