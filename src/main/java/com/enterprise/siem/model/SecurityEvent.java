package com.enterprise.siem.model;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/** Immutable normalized event exchanged between agents and the SIEM. */
public record SecurityEvent(
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

    public SecurityEvent {
        eventId = eventId == null ? UUID.randomUUID() : eventId;
        timestamp = timestamp == null ? Instant.now() : timestamp;
        hostname = requireText(hostname, "hostname");
        agentId = requireText(agentId, "agentId");
        message = requireText(message, "message");
        source = source == null ? "unknown" : source;
        logLevel = logLevel == null ? "INFO" : logLevel;
        eventType = eventType == null ? EventType.UNKNOWN : eventType;
        metadata = metadata == null ? Map.of() : Map.copyOf(metadata);
    }

    public static SecurityEvent of(String hostname, String agentId, String source, String message,
                                   EventType type, String sourceIp, String username) {
        return new SecurityEvent(UUID.randomUUID(), Instant.now(), hostname, agentId, "INFO", source,
                message, sourceIp, null, username, type, Map.of());
    }

    private static String requireText(String value, String name) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(name + " is required");
        return value;
    }
}
