package com.enterprise.siem.detection;
import com.enterprise.siem.model.SecurityEvent;
import com.enterprise.siem.model.Severity;
public interface DetectionRule {
	String getId();
	String getName();
	boolean evaluate(SecurityEvent event, RuleContext context);
	default Severity getSeverity() { return getId().contains("DISTRIBUTED") ? Severity.CRITICAL : getId().contains("SPIKE") ? Severity.MEDIUM : Severity.HIGH; }
}
