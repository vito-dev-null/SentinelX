package com.enterprise.siem.detection;
import com.enterprise.siem.model.*;
import java.util.List;
import java.util.function.Consumer;
import com.enterprise.siem.util.SIEMMetrics;
public final class RuleEngine {
    private final List<DetectionRule> rules; private final RuleContext context = new RuleContext(); private final Consumer<Alert> alertSink; private final SIEMMetrics metrics;
    public RuleEngine(List<DetectionRule> rules, Consumer<Alert> alertSink) { this(rules, alertSink, null); }
    public RuleEngine(List<DetectionRule> rules, Consumer<Alert> alertSink, SIEMMetrics metrics) { this.rules = List.copyOf(rules); this.alertSink = alertSink; this.metrics = metrics; }
    public void process(SecurityEvent event) {
        for (DetectionRule rule : rules) try { if (metrics != null) metrics.ruleEvaluations.increment(); if (rule.evaluate(event, context)) alertSink.accept(new Alert(null, rule.getId(), event.timestamp(), rule.getSeverity(), event.hostname(), event.sourceIp(), rule.getName() + " detected", "OPEN")); } catch (RuntimeException ignored) { if (metrics != null) { metrics.ruleErrors.increment(); metrics.processingErrors.increment(); } }
        if (metrics != null) metrics.eventsProcessed.increment();
        if (metrics != null) metrics.activeCorrelationKeys.set(context.activeKeys());
    }
}
