package com.enterprise.siem;

import com.enterprise.siem.model.EventType;
import com.enterprise.siem.model.SecurityEvent;
import com.enterprise.siem.security.InputValidator;
import com.enterprise.siem.util.JsonUtil;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import java.time.Instant;
import static org.junit.jupiter.api.Assertions.*;

class StrictIngestionTest {
    @Test
    void rejectsMissingRequiredWireFields() throws Exception {
        var event = SecurityEvent.of("node-1", "agent-1", "sshd", "message", EventType.AUTH_FAILURE, "10.0.0.1", "admin");
        var tree = (ObjectNode) JsonUtil.mapper().valueToTree(event);
        tree.remove("eventId");
        var missingId = JsonUtil.write(tree);
        assertThrows(IllegalArgumentException.class, () -> InputValidator.parseStrict(missingId));
        tree = JsonUtil.mapper().valueToTree(event);
        tree.remove("timestamp");
        var missingTimestamp = JsonUtil.write(tree);
        assertThrows(IllegalArgumentException.class, () -> InputValidator.parseStrict(missingTimestamp));
        tree = JsonUtil.mapper().valueToTree(event);
        tree.remove("eventType");
        var missingType = JsonUtil.write(tree);
        assertThrows(IllegalArgumentException.class, () -> InputValidator.parseStrict(missingType));
    }

    @Test
    void rejectsFutureAndControlCharacterPayloads() throws Exception {
        var future = new SecurityEvent(null, Instant.now().plusSeconds(61), "node-1", "agent-1", "INFO", "syslog", "message", null, null, null, EventType.SYSTEM_EVENT, null);
        assertThrows(IllegalArgumentException.class, () -> InputValidator.parseStrict(JsonUtil.write(future)));
        var control = new SecurityEvent(null, Instant.now(), "node-1", "agent-1", "INFO", "syslog", "bad\nmessage", null, null, null, EventType.SYSTEM_EVENT, null);
        assertThrows(IllegalArgumentException.class, () -> InputValidator.parseStrict(JsonUtil.write(control)));
    }
}
