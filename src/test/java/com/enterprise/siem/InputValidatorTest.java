package com.enterprise.siem;

import com.enterprise.siem.model.EventType;
import com.enterprise.siem.model.SecurityEvent;
import com.enterprise.siem.security.InputValidator;
import org.junit.jupiter.api.Test;
import java.time.Instant;
import static org.junit.jupiter.api.Assertions.*;

class InputValidatorTest {
    @Test
    void acceptsNormalizedEvent() {
        var event = SecurityEvent.of("node-1", "agent-1", "sshd", "Accepted publickey", EventType.AUTH_SUCCESS, "10.0.0.1", "admin");
        InputValidator.validate(event);
    }

    @Test
    void rejectsInvalidIpAndOversizedJson() {
        var event = new SecurityEvent(null, Instant.now(), "node-1", "agent-1", "WARN", "sshd", "message", "not-an-ip", null, null, EventType.UNKNOWN, null);
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validate(event));
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateJsonSize("x".repeat(InputValidator.MAX_EVENT_BYTES + 1)));
    }
    @Test
    void rejectsDemoEvents() {
        var event = new SecurityEvent(null, Instant.now(), "node-1", "agent-1", "INFO", "sshd", "Demo event", "10.0.0.1", null, "admin", EventType.AUTH_SUCCESS, java.util.Map.of("demo", "true"));
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validate(event));
    }
}
