package com.enterprise.siem.detection;
import com.enterprise.siem.model.*;
import java.time.Duration;
public final class BruteForceRule implements DetectionRule {
    private final int threshold; private final Duration window; private final Severity severity;
    public BruteForceRule(int threshold, long windowSeconds) { this(threshold, windowSeconds, Severity.HIGH); }
    public BruteForceRule(int threshold, long windowSeconds, Severity severity) { this.threshold = threshold; this.window = Duration.ofSeconds(windowSeconds); this.severity = severity; }
    public String getId() { return "SSH-BRUTE-FORCE"; } public String getName() { return "SSH brute force"; }
    public Severity getSeverity() { return severity; }
    public boolean evaluate(SecurityEvent event, RuleContext context) { return event.eventType() == EventType.AUTH_FAILURE && event.sourceIp() != null && context.recent("brute:" + event.sourceIp(), event, window).size() >= threshold; }
}
