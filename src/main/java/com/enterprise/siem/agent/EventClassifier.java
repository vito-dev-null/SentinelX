package com.enterprise.siem.agent;
import com.enterprise.siem.model.EventType;
import java.util.regex.Pattern;
public final class EventClassifier {
    private static final Pattern FAILURE = Pattern.compile("failed password|authentication failure|invalid user", Pattern.CASE_INSENSITIVE);
    private static final Pattern SUCCESS = Pattern.compile("accepted (password|publickey)|session opened", Pattern.CASE_INSENSITIVE);
    private EventClassifier() { }
    public static EventType classify(String line) {
        if (line == null || line.isBlank()) return EventType.UNKNOWN;
        if (FAILURE.matcher(line).find()) return EventType.AUTH_FAILURE;
        if (SUCCESS.matcher(line).find()) return EventType.AUTH_SUCCESS;
        String value = line.toLowerCase();
        if (value.contains("tcp") || value.contains("udp") || value.contains("connection") || value.contains("firewall")) return EventType.NETWORK_EVENT;
        if (value.contains("sudo") || value.contains("permission") || value.contains("privilege")) return EventType.PRIVILEGE_EVENT;
        if (value.contains("process") || value.contains("exec")) return EventType.PROCESS_EVENT;
        if (value.contains("kernel") || value.contains("system")) return EventType.SYSTEM_EVENT;
        return EventType.UNKNOWN;
    }
}
