package com.teno.onol.analyzer.application.port.out;

import java.util.List;
import java.util.Map;

public interface ManageSessionStatePort {
    String getSessionState(String flowKey);
    Map<String, String> getSessionStates(List<String> flowKeys);
    void updateSessionState(String flowKey, String state);
    void updateSessionStates(Map<String, String> updates);
    void removeSessionState(String flowKey);
    void removeSessionStates(List<String> flowKeys);

    /**
     * 여러 Flow의 패킷 카운트를 1씩 증가시키고, 증가된 값을 반환함 (Atomic Increment)
     * @param flowKeys 카운트를 증가시킬 Flow Key 목록
     * @return Key별 누적 패킷 수 (예: "flow:key" -> 15)
     */
    Map<String, Long> incrementPacketCounts(List<String> flowKeys);
}
