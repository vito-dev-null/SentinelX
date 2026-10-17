package com.enterprise.siem;

import com.enterprise.siem.database.*;
import com.enterprise.siem.detection.RuleEngine;
import com.enterprise.siem.model.*;
import com.enterprise.siem.server.EnterpriseSIEMServer;
import com.enterprise.siem.util.JsonUtil;
import com.enterprise.siem.util.SIEMMetrics;
import org.junit.jupiter.api.Test;
import java.net.Socket;
import java.nio.file.Files;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.Executors;
import static org.junit.jupiter.api.Assertions.*;

class TcpServerTest {
    @Test
    void acceptsEventsFromMultipleAgentsAndRejectsMalformedJson() throws Exception {
        var database = Files.createTempFile("sentinelx", ".db");
        try (var db = new DatabaseManager(database.toString())) {
            var metrics = new SIEMMetrics();
            var server = new EnterpriseSIEMServer(0, new EventRepository(db), new RuleEngine(List.of(), ignored -> { }), metrics);
            var executor = Executors.newVirtualThreadPerTaskExecutor();
            try {
                executor.submit(() -> { try { server.start(); } catch (Exception ignored) { } });
                long deadline = System.currentTimeMillis() + 3000;
                while (server.boundPort() == 0 && System.currentTimeMillis() < deadline) Thread.sleep(10);
                assertTrue(server.boundPort() > 0);
                for (int i = 1; i <= 3; i++) {
                    try (var client = new Socket("127.0.0.1", server.boundPort()); var out = client.getOutputStream()) {
                        var event = new SecurityEvent(null, Instant.now(), "node" + i, "agent" + i, "INFO", "syslog", "kernel connection", null, null, null, EventType.NETWORK_EVENT, null);
                        out.write((JsonUtil.write(event) + "\nnot-json\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));
                        out.flush();
                    }
                }
                Thread.sleep(300);
                assertEquals(3, metrics.eventsPersisted.sum());
                assertEquals(3, metrics.eventsRejected.sum());
            } finally {
                server.close();
                executor.close();
            }
        } finally {
            Files.deleteIfExists(database);
            Files.deleteIfExists(database.resolveSibling(database.getFileName() + "-wal"));
            Files.deleteIfExists(database.resolveSibling(database.getFileName() + "-shm"));
        }
    }
}
