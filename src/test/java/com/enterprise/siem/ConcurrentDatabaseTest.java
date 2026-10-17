package com.enterprise.siem;

import com.enterprise.siem.database.DatabaseManager;
import com.enterprise.siem.database.EventRepository;
import com.enterprise.siem.model.EventType;
import com.enterprise.siem.model.SecurityEvent;
import org.junit.jupiter.api.Test;
import java.nio.file.Files;
import java.util.concurrent.Executors;
import static org.junit.jupiter.api.Assertions.assertEquals;

class ConcurrentDatabaseTest {
    @Test
    void serializesConcurrentWritesWithoutLoss() throws Exception {
        var file = Files.createTempFile("sentinelx-concurrent", ".db");
        try (var database = new DatabaseManager(file.toString())) {
            var repository = new EventRepository(database);
            try (var workers = Executors.newVirtualThreadPerTaskExecutor()) {
                for (int index = 0; index < 32; index++) {
                    int eventNumber = index;
                    workers.submit(() -> {
                        try { repository.save(SecurityEvent.of("node" + eventNumber, "agent" + eventNumber, "test", "event", EventType.SYSTEM_EVENT, null, null), "{}"); }
                        catch (java.sql.SQLException exception) { throw new RuntimeException(exception); }
                    });
                }
            }
            try (var statement = database.connection().createStatement(); var result = statement.executeQuery("select count(*) from events")) {
                result.next();
                assertEquals(32, result.getInt(1));
            }
        } finally {
            Files.deleteIfExists(file);
            Files.deleteIfExists(file.resolveSibling(file.getFileName() + "-wal"));
            Files.deleteIfExists(file.resolveSibling(file.getFileName() + "-shm"));
        }
    }
}
