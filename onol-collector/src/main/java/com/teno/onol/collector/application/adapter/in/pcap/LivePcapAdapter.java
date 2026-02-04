package com.teno.onol.collector.application.adapter.in.pcap;

import com.teno.onol.collector.application.port.in.CollectPacketUseCase;
import com.teno.onol.collector.domain.NetworkInterfaceSelector;
import com.teno.onol.core.domain.PacketEvent;
import com.teno.onol.core.util.PacketUtils;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

@Slf4j
@Component
@Profile("!test")
public class LivePcapAdapter {

    private final CollectPacketUseCase collectPacketUseCase;
    private final NetworkInterfaceSelector networkInterfaceSelector;

    // 설정 값
    private final String configInterfaceName;
    private final int snapLen;
    private final int timeout;

    // 상태 관리
    private PcapHandle currentHandle;
    private PcapNetworkInterface currentInterface;

    private final ExecutorService captureExecutor = Executors.newSingleThreadExecutor();
    private final ExecutorService monitorExecutor = Executors.newSingleThreadExecutor();

    private volatile boolean isRunning = false;
    private volatile boolean isCapturing = false;

    public LivePcapAdapter(
            CollectPacketUseCase collectPacketUseCase,
            NetworkInterfaceSelector networkInterfaceSelector,
            @Value("${onol.collector.interface-name:eth0}") String configInterfaceName,
            @Value("${onol.collector.snaplen:65536}") int snapLen,
            @Value("${onol.collector.timeout:10}") int timeout) {
        this.collectPacketUseCase = collectPacketUseCase;
        this.networkInterfaceSelector = networkInterfaceSelector;
        this.configInterfaceName = configInterfaceName;
        this.snapLen = snapLen;
        this.timeout = timeout;
    }

    @PostConstruct
    public void start() {
        isRunning = true;
        monitorExecutor.submit(this::monitorLoop);
    }

    /**
     * [Supervisor] 주기적으로 최적의 네트워크 인터페이스를 찾아내고 관리함
     */
    private void monitorLoop() {
        log.info("Network Monitor Started. Mode: {}", configInterfaceName);

        while(isRunning) {
            try {
                log.info("Starting Live Pcap Capture on interface: {}", configInterfaceName);

                PcapNetworkInterface bestInterface = findTargetInterface();
                if (shouldSwitchInterface(bestInterface)) {
                    log.info("Network Change Detected! Switching from [{}] to [{}]",
                            currentInterface != null ? currentInterface.getName() : "None",
                            bestInterface != null ? bestInterface.getName() : "None");

                    restartCapture(bestInterface);
                }

                TimeUnit.SECONDS.sleep(5);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                log.error("Error in Network Monitor Loop", e);
            }
        }
    }

    private PcapNetworkInterface findTargetInterface() throws PcapNativeException {
        // 1. 설정에 특정 인터페이스 이름이 지정된 경우 (강제 모드)
        if (!"auto".equalsIgnoreCase(configInterfaceName)) {
            return Pcaps.getDevByName(configInterfaceName);
        }

        // 2. 자동 감지 모드 (Smart Selector 사용)
        List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
        return networkInterfaceSelector.selectBestInterface(allDevs);
    }

    /**
     * 인터페이스 교체가 필요한지 판단
     */
    private boolean shouldSwitchInterface(PcapNetworkInterface newInterface) {
        // 새로운 인터페이스를 못 찾았으면 스위칭 불가 (기존 유지하거나 대기)
        if (newInterface == null) {
            if (currentHandle != null && currentHandle.isOpen()) {
                // 현재 잘 돌고 있으면 유지
                return false;
            }
            // 현재 핸들도 죽어있으면 재시도 필요하지만, 대상이 없으므로 대기
            return false;
        }

        // 1. 현재 캡처가 안 돌고 있으면 무조건 시작
        if (currentHandle == null || !currentHandle.isOpen()) {
            return true;
        }

        // 2. 더 좋은 인터페이스가 나타났으면 교체 (이름이 다르면 교체)
        return !Objects.equals(currentInterface.getName(), newInterface.getName());
    }

    /**
     * [Worker] 기존 캡처를 종료하고 새 인터페이스에서 캡처 시작
     */
    private synchronized void restartCapture(PcapNetworkInterface nif) {
        // 1. 기존 핸들 정리
        stopCapture();

        try {
            currentInterface = nif;
            currentHandle = nif.openLive(snapLen, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, timeout);
            isCapturing = true;

            log.info("Started Live Capture on: {} ({})", nif.getName(), nif.getDescription());

            // 3. 캡처 작업 비동기 실행
            captureExecutor.submit(this::captureLoop);
        } catch (PcapNativeException e) {
            log.error("Failed to open pcap handle for {}", nif.getName(), e);
            currentInterface = null; // 실패 시 초기화하여 다음 루프에서 재시도 유도
        }
    }

    private void stopCapture() {
        isCapturing = false;
        if (currentHandle != null) {
            try {
                // 핸들을 닫으면 captureLoop에서 Exception이 발생하며 종료됨
                currentHandle.close();
            } catch (Exception e) {
                log.warn("Error closing pcap handle", e);
            }
            currentHandle = null;
        }
    }

    /**
     * 실제 패킷을 읽어오는 루프 (별도 스레드에서 실행)
     */
    private void captureLoop() {
        while (isRunning && isCapturing && currentHandle != null && currentHandle.isOpen()) {
            try {
                Packet packet = currentHandle.getNextPacketEx();
                long timestamp = currentHandle.getTimestamp().getTime();

                // Pcap Packet -> PacketEvent 변환
                PacketEvent event = PacketUtils.toEvent(packet, Instant.ofEpochMilli(timestamp));

                collectPacketUseCase.collect(event);
            } catch (java.util.concurrent.TimeoutException e) {
                // 타임아웃은 정상적인 상황일 수 있으므로 무시하고 계속 진행
            } catch (PcapNativeException | NotOpenException e) {
                log.warn("Pcap Handle Error (Interface might be down): {}", e.getMessage());
                isCapturing = false; // 루프 종료 유도 -> Monitor가 감지 후 재시작
            } catch (Exception e) {
                log.error("Unexpected error in capture loop", e);
            }
        }
    }

    @PreDestroy
    public void stop() {
        isRunning = false;
        stopCapture();
        monitorExecutor.shutdownNow();
        captureExecutor.shutdownNow();
    }
}