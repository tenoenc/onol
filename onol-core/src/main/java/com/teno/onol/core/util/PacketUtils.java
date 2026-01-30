package com.teno.onol.core.util;

import com.teno.onol.core.domain.PacketEvent;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import lombok.extern.slf4j.Slf4j;
import org.pcap4j.packet.*;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

@Slf4j
public class PacketUtils {

    // TLS Constants
    private static final int TLS_RECORD_TYPE_HANDSHAKE = 22; // 0x16
    private static final int TLS_HANDSHAKE_TYPE_CLIENT_HELLO = 1; // 0x01
    private static final int TLS_EXTENSION_TYPE_SNI = 0; // 0x0000
    private static final int SNI_HOST_NAME_TYPE = 0;

    // TODO: TCP Reassembly, QUIC / HTTP3 지원, ECH ...

    public static PacketEvent toEvent(Packet packet, Instant timestamp) {
        String srcIp = "0.0.0.0";
        String dstIp = "0.0.0.0";
        int srcPort = 0;
        int dstPort = 0;
        String protocol = "UNKNOWN";
        byte[] payload = new byte[0];
        String domainName = null;
        int tcpFlags = 0;

        // 1. IP Parsing
        if (packet.contains(IpV4Packet.class)) {
            IpV4Packet ipV4 = packet.get(IpV4Packet.class);
            srcIp = ipV4.getHeader().getSrcAddr().getHostAddress();
            dstIp = ipV4.getHeader().getDstAddr().getHostAddress();
            protocol = ipV4.getHeader().getProtocol().name();
        } else if (packet.contains(IpV6Packet.class)) {
            IpV6Packet ipV6 = packet.get(IpV6Packet.class);
            srcIp = ipV6.getHeader().getSrcAddr().getHostAddress();
            dstIp = ipV6.getHeader().getDstAddr().getHostAddress();
            protocol = ipV6.getHeader().getNextHeader().name();
        }

        // 2. TCP/UDP & SNI Parsing
        if (packet.contains(TcpPacket.class)) {
            TcpPacket tcp = packet.get(TcpPacket.class);
            srcPort = tcp.getHeader().getSrcPort().valueAsInt();
            dstPort = tcp.getHeader().getDstPort().valueAsInt();
            protocol = "TCP";
            if (tcp.getHeader().getFin()) tcpFlags |= PacketEvent.FLAG_FIN;
            if (tcp.getHeader().getSyn()) tcpFlags |= PacketEvent.FLAG_SYN;
            if (tcp.getHeader().getRst()) tcpFlags |= PacketEvent.FLAG_RST;
            if (tcp.getHeader().getPsh()) tcpFlags |= PacketEvent.FLAG_PSH;
            if (tcp.getHeader().getAck()) tcpFlags |= PacketEvent.FLAG_ACK;
            if (tcp.getHeader().getUrg()) tcpFlags |= PacketEvent.FLAG_URG;
            if (tcp.getPayload() != null) {
                payload = tcp.getPayload().getRawData();
                domainName = parseSni(payload); // SNI 파싱 호출
            }
        } else if (packet.contains(UdpPacket.class)) {
            UdpPacket udp = packet.get(UdpPacket.class);
            srcPort = udp.getHeader().getSrcPort().valueAsInt();
            dstPort = udp.getHeader().getDstPort().valueAsInt();
            protocol = "UDP";
            if (udp.getPayload() != null) {
                payload = udp.getPayload().getRawData();
            }
        }

        return new PacketEvent(
                timestamp, srcIp, dstIp, srcPort, dstPort, protocol, payload.length, payload, null,
                domainName,
                tcpFlags
        );
    }

    private static String parseSni(byte[] data) {
        if (data == null || data.length < 5) return null;

        ByteBuf buf = Unpooled.wrappedBuffer(data);
        try {
            // 기본 헤더 길이 확인
            if (buf.readableBytes() < 5) return null;

            // 1. Record Header
            int contentType = buf.readUnsignedByte();
            if (contentType != TLS_RECORD_TYPE_HANDSHAKE) return null;
            buf.skipBytes(2); // Version
            int recordLen = buf.readUnsignedShort();

            // 길이 체크 로직 완화 (패킷 파편화 등의 이슈 방지)
            if (buf.readableBytes() < recordLen) return null;

            // 2. Handshake Header
            if (buf.readableBytes() < 4) return null;
            int handshakeType = buf.readUnsignedByte();
            if (handshakeType != TLS_HANDSHAKE_TYPE_CLIENT_HELLO) return null;

            buf.skipBytes(3); // Handshake Length (3 bytes) - Netty skip

            // 3. Client Hello
            if (buf.readableBytes() < 34) return null; // Versions(2) + Random(32)
            buf.skipBytes(2); // Client Version
            buf.skipBytes(32); // Random

            // Session ID
            if (buf.readableBytes() < 1) return null;
            int sessionIdLen = buf.readUnsignedByte();
            if (!safeSkip(buf, sessionIdLen)) return null;

            // Cipher Suites
            if (buf.readableBytes() < 2) return null;
            int cipherSuitesLen = buf.readUnsignedShort();
            if (!safeSkip(buf, cipherSuitesLen)) return null;

            // Compression
            if (buf.readableBytes() < 1) return null;
            int compressionLen = buf.readUnsignedByte();
            if (!safeSkip(buf, compressionLen)) return null;

            // 4. Extensions
            if (buf.readableBytes() < 2) return null;
            int extensionsTotalLen = buf.readUnsignedShort();
            if (buf.readableBytes() < extensionsTotalLen) return null;

            int endIdx = buf.readerIndex() + extensionsTotalLen;

            while (buf.readerIndex() < endIdx) {
                int extensionType = buf.readUnsignedShort();
                int extensionLen = buf.readUnsignedShort();

                if (extensionType == TLS_EXTENSION_TYPE_SNI) {
                    int sniListLen = buf.readUnsignedShort();
                    int sniEnd = buf.readerIndex() + sniListLen;
                    while (buf.readerIndex() < sniEnd) {
                        int nameType = buf.readUnsignedByte();
                        int nameLen = buf.readUnsignedShort();
                        if (nameType == SNI_HOST_NAME_TYPE) {
                            byte[] nameBytes = new byte[nameLen];
                            buf.readBytes(nameBytes);
                            return new String(nameBytes, StandardCharsets.UTF_8);
                        } else {
                            if (!safeSkip(buf, nameLen)) break;
                        }
                    }
                    return null; // SNI 섹션은 찾았으나 호스트 네임 파싱 후 리턴
                } else {
                    if (!safeSkip(buf, extensionLen)) break;
                }
            }
        } catch (Exception e) {
            log.error("SNI Parsing Failed", e);
            // 인덱스 에러가 나더라도 전체 시스템에 영향 주지 않도록 null 리턴
            return null;
        } finally {
            buf.release();
        }
        return null;
    }

    private static boolean safeSkip(ByteBuf buf, int length) {
        if (buf.readableBytes() < length) {
            return false;
        }
        buf.skipBytes(length);
        return true;
    }
}
