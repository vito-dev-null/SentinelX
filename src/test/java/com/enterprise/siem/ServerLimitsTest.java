package com.enterprise.siem;

import com.enterprise.siem.database.DatabaseManager;
import com.enterprise.siem.database.EventRepository;
import com.enterprise.siem.detection.RuleEngine;
import com.enterprise.siem.model.EventType;
import com.enterprise.siem.model.SecurityEvent;
import com.enterprise.siem.server.EnterpriseSIEMServer;
import com.enterprise.siem.util.JsonUtil;
import com.enterprise.siem.util.SIEMMetrics;
import org.junit.jupiter.api.Test;

import java.net.Socket;
import java.nio.file.Files;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

class ServerLimitsTest {
    @Test
    void boundedQueueAndRateLimitDropWithoutCrashing() throws Exception {
        var databaseFile = Files.createTempFile("sentinelx-limits", ".db");
        try (var database = new DatabaseManager(databaseFile.toString())) {
            var metrics = new SIEMMetrics();
            try (var server = new EnterpriseSIEMServer(0, new EventRepository(database), new RuleEngine(List.of(), ignored -> { }), metrics, 2, 1, 65536, null, 1)) {
                Thread.startVirtualThread(() -> { try { server.start(); } catch (Exception ignored) { } });
                long deadline = System.currentTimeMillis() + 3000;
                while (server.boundPort() == 0 && System.currentTimeMillis() < deadline) Thread.sleep(10);
                try (var client = new Socket("127.0.0.1", server.boundPort())) {
                    var event = new SecurityEvent(null, Instant.now(), "node", "agent", "INFO", "test", "event", null, null, null, EventType.SYSTEM_EVENT, null);
                    var json = (JsonUtil.write(event) + "\n" + JsonUtil.write(new SecurityEvent(null, Instant.now(), "node", "agent", "INFO", "test", "event2", null, null, null, EventType.SYSTEM_EVENT, null)) + "\n").getBytes();
                    client.getOutputStream().write(json);
                    client.getOutputStream().flush();
                }
                Thread.sleep(300);
                assertTrue(metrics.eventsDropped.sum() > 0);
            }
        } finally {
            Files.deleteIfExists(databaseFile);
            Files.deleteIfExists(databaseFile.resolveSibling(databaseFile.getFileName() + "-wal"));
            Files.deleteIfExists(databaseFile.resolveSibling(databaseFile.getFileName() + "-shm"));
        }
    }
}
