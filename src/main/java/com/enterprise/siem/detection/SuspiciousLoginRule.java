package com.enterprise.siem.detection;
import com.enterprise.siem.model.*;
import java.time.Duration;
public final class SuspiciousLoginRule implements DetectionRule {
    private final int threshold; private final Duration window; private final Severity severity;
    public SuspiciousLoginRule(long windowSeconds) { this(3, windowSeconds, Severity.HIGH); }
    public SuspiciousLoginRule(long windowSeconds, Severity severity) { this(3, windowSeconds, severity); }
    public SuspiciousLoginRule(int threshold, long windowSeconds, Severity severity) { this.threshold = threshold; window = Duration.ofSeconds(windowSeconds); this.severity = severity; }
    public String getId() { return "SUSPICIOUS-LOGIN"; } public String getName() { return "Repeated failures followed by success"; }
    public Severity getSeverity() { return severity; }
    public boolean evaluate(SecurityEvent event, RuleContext context) {
        if (event.eventType() != EventType.AUTH_SUCCESS) { context.recent("login:" + event.username() + ":" + event.sourceIp(), event, window); return false; }
        var events = context.recent("login:" + event.username() + ":" + event.sourceIp(), event, window);
        int failures = 0; for (SecurityEvent item : events) if (item != event && item.timestamp().compareTo(event.timestamp()) <= 0 && item.eventType() == EventType.AUTH_FAILURE) failures++;
        return failures >= threshold;
    }
}
