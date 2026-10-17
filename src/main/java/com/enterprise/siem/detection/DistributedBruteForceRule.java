package com.enterprise.siem.detection;
import com.enterprise.siem.model.*;
import java.time.Duration;
public final class DistributedBruteForceRule implements DetectionRule {
    private final int threshold; private final Duration window; private final Severity severity; private final boolean totalThreshold;
    public DistributedBruteForceRule(int threshold, long windowSeconds) { this(threshold, windowSeconds, Severity.CRITICAL, false); }
    public DistributedBruteForceRule(int threshold, long windowSeconds, Severity severity) { this(threshold, windowSeconds, severity, false); }
    public DistributedBruteForceRule(int threshold, long windowSeconds, Severity severity, boolean totalThreshold) { this.threshold = threshold; this.window = Duration.ofSeconds(windowSeconds); this.severity = severity; this.totalThreshold = totalThreshold; }
    public String getId() { return "DISTRIBUTED-BRUTE-FORCE"; } public String getName() { return "Distributed brute force"; }
    public Severity getSeverity() { return severity; }
    public boolean evaluate(SecurityEvent event, RuleContext context) {
        if (event.eventType() != EventType.AUTH_FAILURE || event.sourceIp() == null) return false;
        var all = context.recent("distributed:" + event.sourceIp(), event, window);
        var failures = all.stream().filter(e -> e.eventType() == EventType.AUTH_FAILURE).toList();
        if (failures.stream().map(SecurityEvent::agentId).distinct().count() < 2) return false;
        if (totalThreshold) return failures.size() >= threshold;
        return failures.stream().collect(java.util.stream.Collectors.groupingBy(SecurityEvent::agentId)).values().stream().filter(values -> values.size() >= threshold).count() >= 2;
    }
}
