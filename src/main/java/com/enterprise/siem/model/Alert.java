package com.enterprise.siem.model;
import java.time.Instant;
import java.util.UUID;
public record Alert(UUID alertId, String ruleId, Instant timestamp, Severity severity, String hostname, String sourceIp, String description, String status, Instant firstSeen, Instant lastSeen, long occurrences) {
    public Alert { alertId = alertId == null ? UUID.randomUUID() : alertId; timestamp = timestamp == null ? Instant.now() : timestamp; status = status == null ? "OPEN" : status; firstSeen = firstSeen == null ? timestamp : firstSeen; lastSeen = lastSeen == null ? timestamp : lastSeen; if (occurrences < 1) occurrences = 1; }
    public Alert(UUID alertId, String ruleId, Instant timestamp, Severity severity, String hostname, String sourceIp, String description, String status) { this(alertId, ruleId, timestamp, severity, hostname, sourceIp, description, status, timestamp, timestamp, 1); }
    public Alert occurrence(Instant seenAt) { return new Alert(alertId, ruleId, seenAt, severity, hostname, sourceIp, description, status, firstSeen, seenAt, occurrences + 1); }
}
