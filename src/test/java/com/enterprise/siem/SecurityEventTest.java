package com.enterprise.siem;

import com.enterprise.siem.model.EventType;
import com.enterprise.siem.model.SecurityEvent;
import com.enterprise.siem.util.JsonUtil;
import org.junit.jupiter.api.Test;
import java.time.Instant;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;

class SecurityEventTest {
    @Test
    void roundTripsAsIso8601Json() throws Exception {
        SecurityEvent event = new SecurityEvent(UUID.randomUUID(), Instant.parse("2026-08-24T00:00:00Z"),
                "nodo1", "nodo1", "WARN", "sshd", "Failed password for admin from 10.0.0.10",
                "10.0.0.10", null, "admin", EventType.AUTH_FAILURE, null);
        SecurityEvent copy = JsonUtil.read(JsonUtil.write(event), SecurityEvent.class);
        assertEquals(event, copy);
        assertTrue(JsonUtil.write(event).contains("2026-08-24T00:00:00Z"));
    }
}
