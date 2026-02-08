package com.teno.onol.analyzer.domain;

import com.teno.onol.core.domain.PacketEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class TcpSessionTracker {

    public String determineNextState(String currentState, PacketEvent event) {
        int flags = event.tcpFlags();
        if (currentState == null) currentState = "NONE";

        // 상태 전이 (State Machine)
        if ((flags & PacketEvent.FLAG_SYN) != 0 && (flags & PacketEvent.FLAG_ACK) == 0) {
            return "SYN_SENT";
        } else if ((flags & PacketEvent.FLAG_ACK) != 0 && "SYN_SENT".equals(currentState)) {
            return "ESTABLISHED";
        } else if ((flags & PacketEvent.FLAG_FIN) != 0) {
            return "CLOSED";
        }

        return currentState;
    }

    // 양방향 정규화 키 (Canonical Key)
    public String generateFlowKey(PacketEvent event) {
        String endpointA = event.srcIp() + ":" + event.srcPort();
        String endpointB = event.dstIp() + ":" + event.dstPort();

        // 문자열 비교를 통해 항상 순서를 고정함 (A <-> B 와 B <-> A 가 같은 키를 갖도록)
        if (endpointA.compareTo(endpointB) < 0) {
            return endpointA + "<->" + endpointB;
        }  else {
            return endpointB + "<->" + endpointA;
        }
    }
}
