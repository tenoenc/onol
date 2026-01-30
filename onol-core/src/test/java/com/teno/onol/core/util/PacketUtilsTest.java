package com.teno.onol.core.util;

import com.teno.onol.core.domain.PacketEvent;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UnknownPacket;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

public class PacketUtilsTest {

    // Hex String -> Byte Array
    private byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    // 테스트용 가짜 TLS Client Hello 패킷 데이터 (SNI: google.com 포함)
    // 구조: Record(16) -> Handshake(01) -> ... -> Extension SNI(0000) -> google.com
    private final String MOCK_TLS_HEX =
            "16" +       // Record Type: Handshake
                    "0301" +     // Version: TLS 1.0
                    "0042" +     // Record Length: 66 (0x42)
                    "01" +       // Handshake Type: Client Hello
                    "00003e" +   // Length: 62 (0x3e)
                    "0303" +     // Client Version: TLS 1.2
                    "0000000000000000000000000000000000000000000000000000000000000000" + // Random
                    "00" +       // Session ID Len
                    "0002002f" + // Cipher Suites
                    "0100" +     // Compression
                    "0013" +     // Extensions Len: 19 (0x13)
                    "0000" +     // Extension Type: SNI (0x0000)
                    "000f" +     // Extension Len: 15 (0x0f)
                    "000d" +     // SNI List Len: 13 (0x0d)
                    "00" +       // Name Type: HostName (0)
                    "000a" +     // Name Len: 10 (0x0a) -> "google.com" 길이
                    "676f6f676c652e636f6d"; // "google.com" (Hex)

    @Test
    @DisplayName("TLS 패킷을 변환하면 SNI 도메인 이름이 정상적으로 추출되어야 한다")
    void should_ExtractDomainName_When_TlsPacketContainsSniExtension() {
        // given
        byte[] tlsPayload = hexStringToByteArray(MOCK_TLS_HEX);

        // Pcap4J 객체 Mocking (껍데기만 만듦)
        TcpPacket.TcpHeader mockHeader = mock(TcpPacket.TcpHeader.class);
        TcpPacket mockPacket = mock(TcpPacket.class);
        UnknownPacket payloadPacket = UnknownPacket.newPacket(tlsPayload, 0, tlsPayload.length);

        when(mockPacket.getHeader()).thenReturn(mockHeader);
        when(mockPacket.getPayload()).thenReturn(payloadPacket);
        when(mockPacket.contains(TcpPacket.class)).thenReturn(true);
        when(mockPacket.get(TcpPacket.class)).thenReturn(mockPacket);

        when(mockHeader.getSrcPort()).thenReturn(new org.pcap4j.packet.namednumber.TcpPort((short) 443, "https"));
        when(mockHeader.getDstPort()).thenReturn(new org.pcap4j.packet.namednumber.TcpPort((short) 5678, "ephemeral"));

        // when
        PacketEvent event = PacketUtils.toEvent(mockPacket, Instant.now());

        // then
        assertThat(event.domainName()).isEqualTo("google.com");
    }
}
