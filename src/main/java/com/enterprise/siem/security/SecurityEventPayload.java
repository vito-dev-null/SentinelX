package com.enterprise.siem.security;

import com.enterprise.siem.model.EventType;
import com.enterprise.siem.model.SecurityEvent;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/** Untrusted wire payload; required-field validation happens before conversion. */
public record SecurityEventPayload(
        UUID eventId,
        Instant timestamp,
        String hostname,
        String agentId,
        String logLevel,
        String source,
        String message,
        String sourceIp,
        String destinationIp,
        String username,
        EventType eventType,
        Map<String, String> metadata) {
    public SecurityEvent toEvent() {
        return new SecurityEvent(eventId, timestamp, hostname, agentId, logLevel, source,
                message, sourceIp, destinationIp, username, eventType, metadata);
    }
}
