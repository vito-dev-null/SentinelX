package com.enterprise.siem;

import com.enterprise.siem.database.AlertRepository;
import com.enterprise.siem.database.DatabaseManager;
import com.enterprise.siem.database.EventRepository;
import com.enterprise.siem.database.IncidentRepository;
import com.enterprise.siem.model.Alert;
import com.enterprise.siem.model.EventType;
import com.enterprise.siem.model.Incident;
import com.enterprise.siem.model.IncidentStatus;
import com.enterprise.siem.model.SecurityEvent;
import com.enterprise.siem.model.Severity;
import com.enterprise.siem.soc.SocApiServer;
import com.enterprise.siem.util.SIEMMetrics;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SocApiTest {
    @Test
    void exposesReadOnlyOperationalViewsWithFiltersAndPagination() throws Exception {
        Path databaseFile = Files.createTempFile("sentinelx-soc-", ".db");
        try (DatabaseManager database = new DatabaseManager(databaseFile.toString())) {
            SIEMMetrics metrics = new SIEMMetrics();
            metrics.eventsReceived.add(2);
            SecurityEvent first = new SecurityEvent(null, Instant.parse("2026-08-25T00:00:00Z"), "node-a", "node-a", "WARN", "sshd", "failed login", "10.0.0.1", null, null, EventType.AUTH_FAILURE, null);
            SecurityEvent second = new SecurityEvent(null, Instant.parse("2026-08-25T00:01:00Z"), "node-b", "node-b", "INFO", "syslog", "service started", null, null, null, EventType.SYSTEM_EVENT, null);
            EventRepository events = new EventRepository(database); events.save(first, "{}"); events.save(second, "{}");
            Alert alert = new Alert(null, "RULE-1", first.timestamp(), Severity.HIGH, first.hostname(), first.sourceIp(), "failed", "OPEN"); new AlertRepository(database).save(alert);
            Incident incident = new Incident(null, first.timestamp(), Severity.HIGH, "Incident", "details", IncidentStatus.OPEN.name(), "LOG_INCIDENT"); new IncidentRepository(database).save(incident); new IncidentRepository(database).linkAlert(incident, alert);

            try (SocApiServer api = new SocApiServer(0, database, metrics, List.of())) {
                api.start(); assertTrue(api.isLoopbackBound()); HttpClient client = HttpClient.newHttpClient();
                assertStatus(client, api, "/health", 200, "UP");
                assertStatus(client, api, "/api/status", 200, "RUNNING");
                assertStatus(client, api, "/api/network", 200, "NOT_CONFIGURED");
                assertStatus(client, api, "/api/metrics", 200, "eventsReceived");
                assertStatus(client, api, "/api/events?page=1&size=1&hostname=node-a", 200, "node-a");
                assertStatus(client, api, "/api/alerts?size=1", 200, "RULE-1");
                assertStatus(client, api, "/api/incidents?status=OPEN", 200, incident.incidentId().toString());
                assertStatus(client, api, "/api/incidents/" + incident.incidentId(), 200, "timeline");
                assertStatus(client, api, "/api/nodes", 200, "node-a");
                assertStatus(client, api, "/api/rules", 200, "[]");
                assertStatus(client, api, "/api/events?hostname=%27%20OR%201%3D1%20--", 200, "[]");
                assertEquals(404, get(client, api, "/api/../../etc/passwd").statusCode());
                assertEquals(405, request(client, api, "/api/status", "POST").statusCode());
            }
        } finally { Files.deleteIfExists(databaseFile); }
    }

    private static void assertStatus(HttpClient client, SocApiServer api, String path, int expected, String content) throws Exception { var response = get(client, api, path); assertEquals(expected, response.statusCode()); assertTrue(response.body().contains(content), response.body()); }
    private static HttpResponse<String> get(HttpClient client, SocApiServer api, String path) throws Exception { return request(client, api, path, "GET"); }
    private static HttpResponse<String> request(HttpClient client, SocApiServer api, String path, String method) throws Exception { var builder = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + api.boundPort() + path)); HttpRequest request = method.equals("GET") ? builder.GET().build() : builder.method(method, HttpRequest.BodyPublishers.noBody()).build(); return client.send(request, HttpResponse.BodyHandlers.ofString()); }
}
