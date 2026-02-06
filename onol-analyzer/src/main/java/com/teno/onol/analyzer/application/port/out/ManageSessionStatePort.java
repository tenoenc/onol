package com.teno.onol.analyzer.application.port.out;

public interface ManageSessionStatePort {
    String getSessionState(String flowKey);
    void updateSessionState(String flowKey, String state);
    void removeSessionState(String flowKey);
}
