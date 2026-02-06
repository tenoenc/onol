package com.teno.onol.analyzer.domain;

import lombok.Builder;
import lombok.Getter;

import java.time.OffsetDateTime;

@Getter
@Builder
public class PacketLog {
    private OffsetDateTime time; // TimescaleDB는 TIMESTAMPTZ 사용
    private String srcIp;
    private String dstIp;
    private int srcPort;
    private int dstPort;
    private int protocol;
    private int tcpFlags;
    private int payloadLen;
    private byte[] payload;
    private String countryCode;
    private String domainName;
}
