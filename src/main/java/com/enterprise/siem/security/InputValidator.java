package com.enterprise.siem.security;

import com.enterprise.siem.model.EventType;
import com.enterprise.siem.model.SecurityEvent;
import com.enterprise.siem.util.JsonUtil;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.time.Instant;
import java.util.EnumSet;
import java.util.regex.Pattern;

/** Validates normalized events before they cross into persistence and detection. */
public final class InputValidator {
    public static final int MAX_EVENT_BYTES = 65_536;
    public static final int MAX_LINE_BYTES = MAX_EVENT_BYTES;
    private static final int MAX_TEXT = 8_192;
    private static final Pattern HOSTNAME = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,252}");

    private InputValidator() { }

    public static void validateJsonSize(String json) {
        if (json == null || json.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > MAX_EVENT_BYTES) {
            throw new IllegalArgumentException("event exceeds maximum size");
        }
    }

    public static void validate(SecurityEvent event) {
        if (event == null || event.eventId() == null || event.timestamp() == null) {
            throw new IllegalArgumentException("event identity is required");
        }
        Instant now = Instant.now();
        if (event.timestamp().isBefore(now.minus(Duration.ofDays(366))) || event.timestamp().isAfter(now.plusSeconds(60))) {
            throw new IllegalArgumentException("event timestamp is outside the accepted window");
        }
        text(event.hostname(), "hostname");
        text(event.agentId(), "agentId");
        text(event.message(), "message");
        text(event.source(), "source");
        text(event.logLevel(), "logLevel");
        optionalText(event.username(), "username");
        optionalText(event.destinationIp(), "destinationIp");
        if (!HOSTNAME.matcher(event.hostname()).matches()) throw new IllegalArgumentException("invalid hostname");
        if (event.eventType() == null || !EnumSet.allOf(EventType.class).contains(event.eventType())) throw new IllegalArgumentException("invalid event type");
        validateIp(event.sourceIp());
        validateIp(event.destinationIp());
        if (event.metadata().size() > 128) throw new IllegalArgumentException("too many metadata entries");
        if ("true".equalsIgnoreCase(event.metadata().get("demo"))) throw new IllegalArgumentException("demo events are not accepted");
        event.metadata().forEach((key, value) -> { optionalText(key, "metadata key"); optionalText(value, "metadata value"); });
    }

    public static SecurityEvent parseStrict(String json) throws com.fasterxml.jackson.core.JsonProcessingException {
        validateJsonSize(json);
        var tree = JsonUtil.mapper().readTree(json);
        requireField(tree, "eventId");
        requireField(tree, "timestamp");
        requireField(tree, "eventType");
        var event = JsonUtil.mapper().treeToValue(tree, SecurityEventPayload.class).toEvent();
        validate(event);
        return event;
    }

    private static void requireField(com.fasterxml.jackson.databind.JsonNode tree, String name) {
        if (tree == null || !tree.isObject() || !tree.hasNonNull(name)) throw new IllegalArgumentException(name + " is required");
    }

    private static void text(String value, String field) {
        if (value == null || value.isBlank() || value.length() > MAX_TEXT) throw new IllegalArgumentException("invalid " + field);
        if (value.chars().anyMatch(character -> Character.isISOControl(character) && character != '\t')) throw new IllegalArgumentException("invalid control character in " + field);
    }

    private static void optionalText(String value, String field) { if (value != null) text(value, field); }

    private static void validateIp(String value) {
        if (value == null || value.isBlank()) return;
        try {
            if (!InetAddress.getByName(value).getHostAddress().equals(value) && !value.contains(":")) {
                throw new IllegalArgumentException("invalid IP address");
            }
        } catch (UnknownHostException exception) {
            throw new IllegalArgumentException("invalid IP address", exception);
        }
    }
}
