package com.enterprise.siem.detection;
import com.enterprise.siem.model.*;
import java.time.Duration;
public final class TrafficSpikeRule implements DetectionRule {
    private final int threshold; private final Duration window; private final Severity severity;
    public TrafficSpikeRule(int threshold, long windowSeconds) { this(threshold, windowSeconds, Severity.MEDIUM); }
    public TrafficSpikeRule(int threshold, long windowSeconds, Severity severity) { this.threshold = threshold; this.window = Duration.ofSeconds(windowSeconds); this.severity = severity; }
    public String getId() { return "TRAFFIC-SPIKE"; } public String getName() { return "Network traffic spike"; }
    public Severity getSeverity() { return severity; }
    public boolean evaluate(SecurityEvent event, RuleContext context) { return event.eventType() == EventType.NETWORK_EVENT && context.recent("traffic:" + event.hostname(), event, window).size() >= threshold; }
}
