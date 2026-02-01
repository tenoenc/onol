package com.teno.onol.collector.domain;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapNetworkInterface;

import java.net.InetAddress;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

public class SmartNetworkInterfaceTest {

    private final NetworkInterfaceSelector selector = new NetworkInterfaceSelector();

    @Test
    @DisplayName("루프백 인터페이스는 선택 대상에서 제외해야 한다")
    void should_IgnoreLoopbackInterface() {
        // given
        PcapNetworkInterface loopback = createMockInterface("lo0", true, true);
        PcapNetworkInterface real = createMockInterface("en0", false, true);

        // when
        PcapNetworkInterface selected = selector.selectBestInterface(List.of(loopback, real));

        // then
        assertThat(selected.getName()).isEqualTo("en0");
    }

    @Test
    @DisplayName("IP 주소가 없는(Down 상태인) 인터페이스는 제외해야 한다")
    void should_IgnoreInterfaceWithoutIpAddress() {
        // given
        PcapNetworkInterface noIp = createMockInterface("en1", false, true);
        when(noIp.getAddresses()).thenReturn(Collections.emptyList());

        PcapNetworkInterface hasIp = createMockInterface("en0", false, true);

        // when
        PcapNetworkInterface selected = selector.selectBestInterface(List.of(noIp, hasIp));

        // then
        assertThat(selected.getName()).isEqualTo("en0");
    }

    @Test
    @DisplayName("사용 가능한 인터페이스가 여러 개면 첫 번째 것을 선택한다 (단순 정책)")
    void should_SelectFirstAvailable_When_MultipleValid() {
        // given
        PcapNetworkInterface eth0 = createMockInterface("eth0", false, true);
        PcapNetworkInterface wlan0 = createMockInterface("wlan0", false, true);

        // when
        PcapNetworkInterface selected = selector.selectBestInterface(List.of(eth0, wlan0));

        // then (순서상 온 것)
        assertThat(selected.getName()).isEqualTo("eth0");
    }

    @Test
    @DisplayName("가상 인터페이스(Docker, Bridge)는 우선순위에서 배제한다")
    void should_IgnoreVirtualInterfaces() {
        // given
        PcapNetworkInterface docker = createMockInterface("docker0", false, true);
        PcapNetworkInterface real = createMockInterface("eth0", false, true);

        // when
        PcapNetworkInterface selected = selector.selectBestInterface(List.of(docker, real));

        // then
        assertThat(selected.getName()).isEqualTo("eth0");
    }

    private PcapNetworkInterface createMockInterface(String name, boolean isLoopback, boolean isUp) {
        PcapNetworkInterface nif = mock(PcapNetworkInterface.class);
        when(nif.getName()).thenReturn(name);
        when(nif.isLoopBack()).thenReturn(isLoopback);
        when(nif.isUp()).thenReturn(isUp);

        // 가짜 IP 주소 주입 (IP가 있어야 유효한 인터페이스로 간주)
        if (isUp) {
            PcapAddress addr = mock(PcapAddress.class);
            when(addr.getAddress()).thenReturn(mock(InetAddress.class));
            when(nif.getAddresses()).thenReturn(List.of(addr));
        } else {
            when(nif.getAddresses()).thenReturn(Collections.emptyList());
        }
        return nif;
    }
}
