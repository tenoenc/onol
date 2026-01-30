package com.teno.onol.core.domain;

import lombok.Builder;

import java.time.Instant;

@Builder
public record PacketEvent(
        Instant timestamp, // 패킷 캡처 시각
        String srcIp,
        String dstIp,
        int srcPort,
        int dstPort,
        String protocol, // TCP, UDP, ICMP ...
        int payloadLen,
        byte[] payload, // 실제 데이터
        String countryCode, // GeoIP 결과
        String domainName, // SNI 파싱 결과 (HTTPS 도메인)
        int tcpFlags // SYN, ACK ...
) {
    // TCP Flags BitMask Constants
    public static final int FLAG_FIN = 0x01; // 1
    public static final int FLAG_SYN = 0x02; // 2
    public static final int FLAG_RST = 0x04; // 4
    public static final int FLAG_PSH = 0x08; // 8
    public static final int FLAG_ACK = 0x10; // 16
    public static final int FLAG_URG = 0x20; // 32
}