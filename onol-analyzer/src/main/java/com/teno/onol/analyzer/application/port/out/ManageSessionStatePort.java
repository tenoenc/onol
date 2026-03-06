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
}
