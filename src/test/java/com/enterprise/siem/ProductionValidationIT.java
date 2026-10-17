package com.enterprise.siem;

import com.enterprise.siem.agent.SIEMClient;
import com.enterprise.siem.alert.AlertManager;
import com.enterprise.siem.database.DatabaseManager;
import com.enterprise.siem.database.EventRepository;
import com.enterprise.siem.database.AlertRepository;
import com.enterprise.siem.database.IncidentRepository;
import com.enterprise.siem.detection.DistributedBruteForceRule;
import com.enterprise.siem.detection.RuleEngine;
import com.enterprise.siem.model.EventType;
import com.enterprise.siem.model.Alert;
import com.enterprise.siem.model.Incident;
import com.enterprise.siem.model.IncidentStatus;
import com.enterprise.siem.model.Severity;
import com.enterprise.siem.model.SecurityEvent;
import com.enterprise.siem.security.TlsConfiguration;
import com.enterprise.siem.server.EnterpriseSIEMServer;
import com.enterprise.siem.security.FileSecurityAuditLogger;
import com.enterprise.siem.soar.ProcessExecutor;
import com.enterprise.siem.soar.ResponseManager;
import com.enterprise.siem.util.JsonUtil;
import com.enterprise.siem.util.SIEMMetrics;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.ResultSet;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class ProductionValidationIT {
    private static final String PASSWORD = "validation-only";

    @Test
    void tlsAndMutualTlsRejectUntrustedAndMissingClientCertificates() throws Exception {
        Path directory = Files.createTempDirectory("sentinelx-tls-");
        CertificateMaterial material = CertificateMaterial.create(directory);
        Path databaseFile = directory.resolve("tls.db");
        try (DatabaseManager database = new DatabaseManager(databaseFile.toString());
             EnterpriseSIEMServer server = server(database, new SIEMMetrics(), material.serverConfiguration(true))) {
            start(server);
            try (SIEMClient client = new SIEMClient("localhost", server.boundPort(), 65536, material.clientConfiguration("node1"))) {
                client.send(event("node1", "tls-valid", "10.0.0.1"));
            }
            try (SIEMClient client = new SIEMClient("localhost", server.boundPort(), 65536, material.untrustedClientConfiguration())) {
                client.send(event("untrusted", "tls-untrusted", "10.0.0.2"));
            }
            try (SIEMClient client = new SIEMClient("localhost", server.boundPort(), 65536, material.expiredClientConfiguration())) {
                try { client.send(event("expired", "tls-expired", "10.0.0.3")); } catch (IOException expected) { }
            }
            Thread.sleep(300);
            assertEquals(1, count(database, "events"), "untrusted client event must not be accepted");
            SSLContext trustOnly = material.trustOnlyContext();
            try (SSLSocket socket = (SSLSocket) trustOnly.getSocketFactory().createSocket("localhost", server.boundPort())) {
                try { socket.startHandshake(); } catch (IOException ignored) { }
            }
            Thread.sleep(300);
            assertEquals(1, count(database, "events"), "client without certificate must not be accepted");
        }
        deleteTree(directory);
    }

    @Test
    void threeConcurrentNodesPersistAllEventsAndGenerateDistributedAlerts() throws Exception {
        Path databaseFile = Files.createTempFile("sentinelx-multi-", ".db");
        try (DatabaseManager database = new DatabaseManager(databaseFile.toString())) {
            SIEMMetrics metrics = new SIEMMetrics();
            var response = new ResponseManager(true, new ProcessExecutor(), new FileSecurityAuditLogger(databaseFile + ".audit"), metrics);
            var incidents = new com.enterprise.siem.incident.IncidentManager(new IncidentRepository(database), response, metrics);
            var alerts = new AlertManager(new AlertRepository(database), incidents, metrics);
            var rules = new RuleEngine(List.of(new DistributedBruteForceRule(10, 60, com.enterprise.siem.model.Severity.CRITICAL, true)), alerts::accept, metrics);
            try (EnterpriseSIEMServer server = new EnterpriseSIEMServer(0, new EventRepository(database), rules, metrics, 10, 10000, 65536, null, 1024)) {
                start(server);
                CountDownLatch ready = new CountDownLatch(3);
                CountDownLatch done = new CountDownLatch(3);
                for (int node = 1; node <= 3; node++) {
                    int current = node;
                    Thread.startVirtualThread(() -> {
                        try (SIEMClient client = new SIEMClient("127.0.0.1", server.boundPort(), 65536)) {
                            ready.countDown();
                            ready.await(3, TimeUnit.SECONDS);
                            for (int index = 0; index < 100; index++) client.send(event("node" + current, "multi-" + current + "-" + index, "10.0.0.9"));
                        } catch (Exception exception) { throw new RuntimeException(exception); } finally { done.countDown(); }
                    });
                }
                assertTrue(done.await(20, TimeUnit.SECONDS));
                await(metrics, 300, 5000);
                assertEquals(300, metrics.eventsReceived.sum());
                assertEquals(300, metrics.eventsPersisted.sum());
                assertEquals(300, metrics.eventsProcessed.sum());
                assertTrue(metrics.alertsGenerated.sum() > 0);
                assertTrue(count(database, "alerts") > 0);
                assertTrue(count(database, "incidents") > 0);
            }
        } finally { deleteDatabase(databaseFile); }
    }

    @Test
    void realTcpPipelineProcessesTenThousandEventsAndDrainsOnShutdown() throws Exception {
        Path databaseFile = Files.createTempFile("sentinelx-load-", ".db");
        SIEMMetrics metrics = new SIEMMetrics();
        EnterpriseSIEMServer server = null;
        DatabaseManager database = new DatabaseManager(databaseFile.toString());
        try {
            server = new EnterpriseSIEMServer(0, new EventRepository(database), new RuleEngine(List.of(), ignored -> { }, metrics), metrics, 4, 20000, 65536, null, 20_000);
            start(server);
            long startedAt = System.nanoTime();
            try (SIEMClient client = new SIEMClient("127.0.0.1", server.boundPort(), 65536)) {
                for (int index = 0; index < 10_000; index++) client.send(event("load-node", "load-" + index, "10.0.0.10"));
            }
            await(metrics, 10_000, 90_000);
            server.close();
            await(metrics, 10_000, 90_000);
            assertEquals(10_000, metrics.eventsReceived.sum());
            assertEquals(10_000, metrics.eventsPersisted.sum());
            assertEquals(10_000, metrics.eventsProcessed.sum());
            assertTrue(metrics.queueHighWaterMark.get() <= 20_000);
                long durationMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt);
                System.out.printf("10k load: durationMs=%d eventsPerSecond=%.2f eventsPersisted=%d eventsDropped=%d queueHighWaterMark=%d%n",
                    durationMs, durationMs == 0 ? 0.0 : 10_000_000.0 / durationMs, metrics.eventsPersisted.sum(), metrics.eventsDropped.sum(), metrics.queueHighWaterMark.get());
            try (DatabaseManager reopened = new DatabaseManager(databaseFile.toString());
                 var statement = reopened.connection().createStatement();
                 ResultSet result = statement.executeQuery("select count(*) from events")) {
                assertTrue(result.next());
                assertEquals(10_000, result.getInt(1));
            }
        } finally {
            if (server != null) server.close();
            database.close();
            deleteDatabase(databaseFile);
        }
    }

    @Test
    void rateAndSizeLimitsRejectWithoutStoppingOtherClients() throws Exception {
        Path databaseFile = Files.createTempFile("sentinelx-limits-", ".db");
        try (DatabaseManager database = new DatabaseManager(databaseFile.toString())) {
            SIEMMetrics metrics = new SIEMMetrics();
            try (EnterpriseSIEMServer server = new EnterpriseSIEMServer(0, new EventRepository(database), new RuleEngine(List.of(), ignored -> { }), metrics, 2, 1, 1024, null, 16)) {
                start(server);
                try (SIEMClient limited = new SIEMClient("127.0.0.1", server.boundPort(), 65536)) {
                    limited.send(event("limited", "one", "10.0.0.1"));
                    try (var raw = new java.net.Socket("127.0.0.1", server.boundPort())) {
                        raw.getOutputStream().write(("x".repeat(2000) + "\n").getBytes(StandardCharsets.UTF_8));
                        raw.getOutputStream().flush();
                    }
                }
                Thread.sleep(1100);
                try (SIEMClient other = new SIEMClient("127.0.0.1", server.boundPort(), 65536)) { other.send(event("other", "accepted", "10.0.0.2")); }
                Thread.sleep(300);
                long deadline = System.currentTimeMillis() + 3000;
                while (metrics.eventsReceived.sum() < 2 && System.currentTimeMillis() < deadline) Thread.sleep(10);
                assertTrue(metrics.eventsDropped.sum() > 0 || metrics.oversizedEvents.sum() > 0);
                assertTrue(metrics.eventsReceived.sum() >= 2, "a healthy client must still be processed");
            }
        } finally { deleteDatabase(databaseFile); }
    }

    @Test
    void maxConnectionsRejectsOverflowAndReleasesSlots() throws Exception {
        Path databaseFile = Files.createTempFile("sentinelx-connections-", ".db");
        try (DatabaseManager database = new DatabaseManager(databaseFile.toString())) {
            SIEMMetrics metrics = new SIEMMetrics();
            try (EnterpriseSIEMServer server = new EnterpriseSIEMServer(0, new EventRepository(database), new RuleEngine(List.of(), ignored -> { }), metrics, 2, 1000, 65536, null, 16)) {
                start(server);
                java.net.Socket first = new java.net.Socket("127.0.0.1", server.boundPort());
                java.net.Socket second = new java.net.Socket("127.0.0.1", server.boundPort());
                java.net.Socket third = new java.net.Socket("127.0.0.1", server.boundPort());
                try {
                    waitFor(() -> metrics.activeConnections.get() == 2, 3000);
                    assertTrue(metrics.eventsRejected.sum() >= 1);
                    first.close();
                    waitFor(() -> metrics.activeConnections.get() < 2, 3000);
                    try (var replacement = new java.net.Socket("127.0.0.1", server.boundPort())) {
                        waitFor(() -> metrics.activeConnections.get() == 2, 3000);
                    }
                } finally { second.close(); third.close(); }
            }
        } finally { deleteDatabase(databaseFile); }
    }

    @Test
    void shutdownDuringBacklogAccountsForEveryReceivedEvent() throws Exception {
        Path databaseFile = Files.createTempFile("sentinelx-shutdown-", ".db");
        try (DatabaseManager database = new DatabaseManager(databaseFile.toString())) {
            SIEMMetrics metrics = new SIEMMetrics();
            var slowRule = new com.enterprise.siem.detection.DetectionRule() {
                public String getId() { return "SLOW"; }
                public String getName() { return "slow"; }
                public boolean evaluate(SecurityEvent event, com.enterprise.siem.detection.RuleContext context) { try { Thread.sleep(20); } catch (InterruptedException e) { Thread.currentThread().interrupt(); } return false; }
            };
            try (EnterpriseSIEMServer server = new EnterpriseSIEMServer(0, new EventRepository(database), new RuleEngine(List.of(slowRule), ignored -> { }, metrics), metrics, 2, 10000, 65536, null, 4)) {
                start(server);
                try (var socket = new java.net.Socket("127.0.0.1", server.boundPort()); var writer = new java.io.BufferedWriter(new java.io.OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8))) {
                    for (int index = 0; index < 100; index++) { writer.write(event("shutdown", "shutdown-" + index, "10.0.0.30")); writer.newLine(); }
                    writer.flush();
                }
                waitFor(() -> metrics.eventsReceived.sum() >= 10, 3000);
                server.close();
                assertEquals(metrics.eventsReceived.sum(), metrics.eventsProcessed.sum() + metrics.eventsDropped.sum());
                assertEquals(0, metrics.queueSize.get());
            }
        } finally { deleteDatabase(databaseFile); }
    }

    @Test
    void ruleExceptionsDoNotPreventFollowingRules() throws Exception {
        AtomicInteger executedB = new AtomicInteger();
        AtomicInteger executedC = new AtomicInteger();
        var throwing = new com.enterprise.siem.detection.DetectionRule() { public String getId() { return "A"; } public String getName() { return "A"; } public boolean evaluate(SecurityEvent e, com.enterprise.siem.detection.RuleContext c) { throw new RuntimeException("test"); } };
        var ruleB = new com.enterprise.siem.detection.DetectionRule() { public String getId() { return "B"; } public String getName() { return "B"; } public boolean evaluate(SecurityEvent e, com.enterprise.siem.detection.RuleContext c) { executedB.incrementAndGet(); return false; } };
        var ruleC = new com.enterprise.siem.detection.DetectionRule() { public String getId() { return "C"; } public String getName() { return "C"; } public boolean evaluate(SecurityEvent e, com.enterprise.siem.detection.RuleContext c) { executedC.incrementAndGet(); return false; } };
        SIEMMetrics metrics = new SIEMMetrics();
        new RuleEngine(List.of(throwing, ruleB, ruleC), ignored -> { }, metrics).process(new SecurityEvent(null, Instant.now(), "node", "agent", "WARN", "test", "message", "10.0.0.1", null, null, EventType.AUTH_FAILURE, null));
        assertEquals(1, metrics.ruleErrors.sum()); assertEquals(1, executedB.get()); assertEquals(1, executedC.get());
    }

    @Test
    void deduplicationPersistsOccurrencesAndTimeBounds() throws Exception {
        Path databaseFile = Files.createTempFile("sentinelx-dedup-", ".db");
        try (DatabaseManager database = new DatabaseManager(databaseFile.toString())) {
            SIEMMetrics metrics = new SIEMMetrics();
            var response = new ResponseManager(true, new ProcessExecutor(), new FileSecurityAuditLogger(databaseFile + ".audit"), metrics);
            var incidents = new com.enterprise.siem.incident.IncidentManager(new IncidentRepository(database), response, metrics);
            var manager = new AlertManager(new AlertRepository(database), incidents, metrics);
            Instant first = Instant.now().minusSeconds(30);
            for (int index = 0; index < 100; index++) manager.accept(new Alert(null, "RULE", first.plusSeconds(index), Severity.HIGH, "host", "10.0.0.5", "same", "OPEN"));
            try (var statement = database.connection().createStatement(); var result = statement.executeQuery("select count(*), first_seen, last_seen, occurrences from alerts")) {
                assertTrue(result.next()); assertEquals(1, result.getInt(1)); assertEquals(first.toString(), result.getString(2)); assertEquals(first.plusSeconds(99).toString(), result.getString(3)); assertEquals(100, result.getInt(4));
            }
        } finally { deleteDatabase(databaseFile); }
    }

    @Test
    void incidentLifecycleSurvivesDatabaseReopen() throws Exception {
        Path databaseFile = Files.createTempFile("sentinelx-lifecycle-", ".db");
        java.util.UUID id;
        try (DatabaseManager database = new DatabaseManager(databaseFile.toString())) {
            SIEMMetrics metrics = new SIEMMetrics();
            var manager = new com.enterprise.siem.incident.IncidentManager(new IncidentRepository(database), new ResponseManager(true, new ProcessExecutor(), new FileSecurityAuditLogger(databaseFile + ".audit"), metrics), metrics);
            Incident original = new Incident(null, Instant.now(), Severity.CRITICAL, "test", "test", IncidentStatus.OPEN.name(), "LOG_INCIDENT"); id = original.incidentId(); new IncidentRepository(database).save(original);
            assertEquals(IncidentStatus.ACKNOWLEDGED.name(), manager.transition(id, IncidentStatus.ACKNOWLEDGED).status());
            Incident resolved = manager.transition(id, IncidentStatus.RESOLVED); assertNotNull(resolved.resolvedAt()); assertTrue(resolved.updatedAt().compareTo(resolved.createdAt()) >= 0);
        }
        try (DatabaseManager reopened = new DatabaseManager(databaseFile.toString())) { Incident persisted = new IncidentRepository(reopened).find(id).orElseThrow(); assertEquals(IncidentStatus.RESOLVED.name(), persisted.status()); assertNotNull(persisted.resolvedAt()); }
        finally { deleteDatabase(databaseFile); }
    }

    @Test
    void soarTreatsInjectionLikeTextAndDoesNotExecuteIt() throws Exception {
        Path directory = Files.createTempDirectory("sentinelx-soar-"); Path marker = directory.resolve("marker");
        try {
            var audit = new FileSecurityAuditLogger(directory.resolve("audit.log").toString());
            var response = new ResponseManager(true, new ProcessExecutor(), audit, new SIEMMetrics());
            String payload = "$(touch " + marker + ") && touch " + marker;
            Incident incident = new Incident(null, Instant.now(), Severity.CRITICAL, "incident", payload, IncidentStatus.OPEN.name(), "SIMULATE_ISOLATION");
            response.respond(incident, new Alert(null, "RULE", Instant.now(), Severity.CRITICAL, "host", null, payload, "OPEN"));
            assertFalse(Files.exists(marker));
        } finally { deleteTree(directory); }
    }

    private static EnterpriseSIEMServer server(DatabaseManager database, SIEMMetrics metrics, TlsConfiguration tls) {
        return new EnterpriseSIEMServer(0, new EventRepository(database), new RuleEngine(List.of(), ignored -> { }, metrics), metrics, 10, 1000, 65536, tls, 128);
    }

    private static void start(EnterpriseSIEMServer server) throws Exception {
        Thread.startVirtualThread(() -> { try { server.start(); } catch (IOException ignored) { } });
        long deadline = System.currentTimeMillis() + 5000;
        while (server.boundPort() == 0 && System.currentTimeMillis() < deadline) Thread.sleep(10);
        assertTrue(server.boundPort() > 0);
    }

    private static void await(SIEMMetrics metrics, long expected, long timeoutMs) throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (metrics.eventsProcessed.sum() < expected && System.currentTimeMillis() < deadline) Thread.sleep(10);
        assertEquals(expected, metrics.eventsProcessed.sum());
    }

    private static void waitFor(java.util.function.BooleanSupplier condition, long timeoutMs) throws Exception { long deadline = System.currentTimeMillis() + timeoutMs; while (!condition.getAsBoolean() && System.currentTimeMillis() < deadline) Thread.sleep(10); assertTrue(condition.getAsBoolean()); }

    private static long count(DatabaseManager database, String table) throws Exception {
        try (var statement = database.connection().createStatement(); var result = statement.executeQuery("select count(*) from " + table)) {
            assertTrue(result.next());
            return result.getLong(1);
        }
    }

    private static String event(String agent, String id, String sourceIp) throws Exception {
        return JsonUtil.write(new SecurityEvent(java.util.UUID.fromString(java.util.UUID.nameUUIDFromBytes(id.getBytes(StandardCharsets.UTF_8)).toString()), Instant.now(), agent, agent, "WARN", "test", "validation event", sourceIp, null, null, EventType.AUTH_FAILURE, null));
    }

    private static void deleteDatabase(Path path) throws IOException { Files.deleteIfExists(path); Files.deleteIfExists(Path.of(path + "-wal")); Files.deleteIfExists(Path.of(path + "-shm")); }
    private static void deleteTree(Path directory) throws IOException { try (var paths = Files.walk(directory)) { paths.sorted(java.util.Comparator.reverseOrder()).forEach(path -> { try { Files.deleteIfExists(path); } catch (IOException ignored) { } }); } }

    private static final class CertificateMaterial {
        private final Path directory;
        private CertificateMaterial(Path directory) { this.directory = directory; }
        static CertificateMaterial create(Path directory) throws Exception {
            run(directory, "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=SentinelX-Test-CA", "-keyout", "ca.key", "-out", "ca.crt");
            issue(directory, "server", "localhost", "serverAuth", "subjectAltName=DNS:localhost,IP:127.0.0.1");
            issue(directory, "node1", "node1", "clientAuth", "");
            issue(directory, "expired", "expired", "clientAuth", "", 0);
            run(directory, "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=Untrusted-CA", "-keyout", "untrusted-ca.key", "-out", "untrusted-ca.crt");
            issueWithCa(directory, "untrusted", "untrusted", "untrusted-ca.crt", "untrusted-ca.key", "clientAuth", "");
            for (String name : List.of("server", "node1", "expired", "untrusted")) run(directory, "openssl", "pkcs12", "-export", "-name", name, "-inkey", name + ".key", "-in", name + ".crt", "-certfile", "ca.crt", "-out", name + ".p12", "-passout", "pass:" + PASSWORD);
            truststore(directory, "server-truststore.p12", "ca.crt");
            truststore(directory, "client-truststore.p12", "ca.crt");
            truststore(directory, "untrusted-truststore.p12", "ca.crt");
            return new CertificateMaterial(directory);
        }
        private static void issue(Path d, String name, String cn, String usage, String san) throws Exception { issueWithCa(d, name, cn, "ca.crt", "ca.key", usage, san, 2); }
        private static void issue(Path d, String name, String cn, String usage, String san, int days) throws Exception { issueWithCa(d, name, cn, "ca.crt", "ca.key", usage, san, days); }
        private static void issueWithCa(Path d, String name, String cn, String caCert, String caKey, String usage, String san) throws Exception {
            issueWithCa(d, name, cn, caCert, caKey, usage, san, 2);
        }
        private static void issueWithCa(Path d, String name, String cn, String caCert, String caKey, String usage, String san, int days) throws Exception {
            run(d, "openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=" + cn, "-keyout", name + ".key", "-out", name + ".csr");
            Path ext = d.resolve(name + ".ext"); Files.writeString(ext, "extendedKeyUsage=" + usage + (san.isBlank() ? "" : "\n" + san));
            run(d, "openssl", "x509", "-req", "-in", name + ".csr", "-CA", caCert, "-CAkey", caKey, "-CAcreateserial", "-days", String.valueOf(days), "-out", name + ".crt", "-extfile", ext.getFileName().toString());
        }
        private static void truststore(Path d, String name, String certificate) throws Exception { run(d, "keytool", "-importcert", "-noprompt", "-alias", "ca", "-file", certificate, "-keystore", name, "-storetype", "PKCS12", "-storepass", PASSWORD); }
        TlsConfiguration serverConfiguration(boolean mtls) { return new TlsConfiguration(true, directory.resolve("server.p12"), PASSWORD.toCharArray(), directory.resolve("server-truststore.p12"), PASSWORD.toCharArray(), mtls); }
        TlsConfiguration clientConfiguration(String ignored) { return new TlsConfiguration(true, directory.resolve("node1.p12"), PASSWORD.toCharArray(), directory.resolve("client-truststore.p12"), PASSWORD.toCharArray(), false); }
        TlsConfiguration untrustedClientConfiguration() { return new TlsConfiguration(true, directory.resolve("untrusted.p12"), PASSWORD.toCharArray(), directory.resolve("untrusted-truststore.p12"), PASSWORD.toCharArray(), false); }
        TlsConfiguration expiredClientConfiguration() { return new TlsConfiguration(true, directory.resolve("expired.p12"), PASSWORD.toCharArray(), directory.resolve("client-truststore.p12"), PASSWORD.toCharArray(), false); }
        SSLContext trustOnlyContext() throws Exception { var store=java.security.KeyStore.getInstance("PKCS12"); try(var input=Files.newInputStream(directory.resolve("client-truststore.p12"))){store.load(input,PASSWORD.toCharArray());} var trusts=TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); trusts.init(store); SSLContext context=SSLContext.getInstance("TLS"); context.init(null,trusts.getTrustManagers(),null); return context; }
        private static void run(Path directory, String... command) throws Exception { Process process = new ProcessBuilder(command).directory(directory.toFile()).redirectErrorStream(true).start(); if (process.waitFor() != 0) throw new IOException("certificate command failed: " + String.join(" ", command)); }
    }
}
