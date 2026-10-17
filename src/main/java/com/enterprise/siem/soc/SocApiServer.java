package com.enterprise.siem.soc;

import com.enterprise.siem.database.DatabaseManager;
import com.enterprise.siem.detection.DetectionRule;
import com.enterprise.siem.util.JsonUtil;
import com.enterprise.siem.util.SIEMMetrics;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

/** Read-only HTTP boundary for the SOC console. */
public final class SocApiServer implements AutoCloseable {
    private final DatabaseManager database;
    private final SIEMMetrics metrics;
    private final NetworkTelemetry network;
    private final NetworkFlowCollector flowCollector;
    private final List<DetectionRule> rules;
    private final boolean tlsEnabled;
    private final Instant startedAt = Instant.now();
    private final HttpServer server;
    private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
    private final AtomicBoolean workerBusy = new AtomicBoolean();

    public SocApiServer(int port, DatabaseManager database, SIEMMetrics metrics, List<DetectionRule> rules)
            throws IOException {
        this(port, database, metrics, rules, false);
    }

    public SocApiServer(int port, DatabaseManager database, SIEMMetrics metrics, List<DetectionRule> rules,
            boolean tlsEnabled) throws IOException {
        this("127.0.0.1", port, database, metrics, rules, tlsEnabled, null);
    }

    public SocApiServer(String host, int port, DatabaseManager database, SIEMMetrics metrics, List<DetectionRule> rules,
            boolean tlsEnabled) throws IOException {
        this(host, port, database, metrics, rules, tlsEnabled, null);
    }

    public SocApiServer(String host, int port, DatabaseManager database, SIEMMetrics metrics, List<DetectionRule> rules,
            boolean tlsEnabled, NetworkTelemetry network) throws IOException {
        this(host, port, database, metrics, rules, tlsEnabled, network, null);
    }

    public SocApiServer(String host, int port, DatabaseManager database, SIEMMetrics metrics, List<DetectionRule> rules,
            boolean tlsEnabled, NetworkTelemetry network, NetworkFlowCollector flowCollector) throws IOException {
        this.database = database;
        this.metrics = metrics;
        this.rules = List.copyOf(rules);
        this.tlsEnabled = tlsEnabled;
        this.network = network;
        this.flowCollector = flowCollector;
        if (host == null || host.isBlank())
            throw new IllegalArgumentException("soc.host must not be blank");
        server = HttpServer.create(new InetSocketAddress(host, port), 32);
        server.createContext("/api/", this::handleApi);
        server.createContext("/health", this::handleHealth);
        server.createContext("/", this::handleConsole);
        server.setExecutor(executor);
    }

    public void start() {
        server.start();
    }

    public int boundPort() {
        return server.getAddress().getPort();
    }

    public boolean isLoopbackBound() {
        return server.getAddress().getAddress().isLoopbackAddress();
    }

    private void handleHealth(HttpExchange exchange) throws IOException {
        try {
            if (!"GET".equals(exchange.getRequestMethod())) {
                respond(exchange, 405, Map.of("error", "read-only API"));
                return;
            }
            respond(exchange, 200, Map.of("status", "UP"));
        } finally {
            exchange.close();
        }
    }

    private void handleApi(HttpExchange exchange) throws IOException {
        try {
            String path = exchange.getRequestURI().getPath();
            if (path.equals("/api/worker/lease") && "POST".equals(exchange.getRequestMethod())) {
                workerLease(exchange);
                return;
            }
            if (!"GET".equals(exchange.getRequestMethod())) {
                respond(exchange, 405, Map.of("error", "read-only API"));
                return;
            }
            Map<String, String> query = query(exchange.getRequestURI());
            if (path.equals("/api/status"))
                respond(exchange, 200, status());
            else if (path.equals("/api/time"))
                respond(exchange, 200, time());
            else if (path.equals("/api/network"))
                respond(exchange, 200, networkStatus());
            else if (path.equals("/api/capture-test"))
                respond(exchange, 200, flowCollector == null ? Map.of("captureOpenResult", "NO_INTERFACE")
                        : flowCollector.captureTest());
            else if (path.equals("/api/network/metrics"))
                respond(exchange, 200, networkMetrics());
            else if (path.equals("/api/flows"))
                respond(exchange, 200, networkFlows());
            else if (path.equals("/api/metrics"))
                respond(exchange, 200, metrics());
            else if (path.equals("/api/events"))
                respond(exchange, 200, events(query));
            else if (path.equals("/api/alerts"))
                respond(exchange, 200, alerts(query));
            else if (path.equals("/api/incidents"))
                respond(exchange, 200, incidents(query));
            else if (path.startsWith("/api/incidents/"))
                respond(exchange, 200, incident(path.substring("/api/incidents/".length())));
            else if (path.equals("/api/nodes"))
                respond(exchange, 200, nodes());
            else if (path.equals("/api/rules"))
                respond(exchange, 200, rules());
            else if (path.equals("/api/worker/status"))
                respond(exchange, 200, Map.of("status", workerBusy.get() ? "BUSY" : "AVAILABLE"));
            else
                respond(exchange, 404, Map.of("error", "not found"));
        } catch (IllegalArgumentException exception) {
            respond(exchange, 400, Map.of("error", exception.getMessage()));
        } catch (Exception exception) {
            respond(exchange, 500, Map.of("error", "internal error"));
        } finally {
            exchange.close();
        }
    }

    private void workerLease(HttpExchange exchange) throws IOException {
        boolean release = "release".equalsIgnoreCase(query(exchange.getRequestURI()).get("action"));
        if (release) {
            workerBusy.set(false);
            respond(exchange, 200, Map.of("status", "AVAILABLE"));
        } else if (workerBusy.compareAndSet(false, true)) {
            respond(exchange, 200, Map.of("status", "BUSY"));
        } else {
            respond(exchange, 409, Map.of("status", "BUSY"));
        }
    }

    private void handleConsole(HttpExchange exchange) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod()) || !("/".equals(exchange.getRequestURI().getPath())
                || "/dashboard".equals(exchange.getRequestURI().getPath())
                || "/events".equals(exchange.getRequestURI().getPath())
                || "/alerts".equals(exchange.getRequestURI().getPath())
                || "/incidents".equals(exchange.getRequestURI().getPath())
                || "/nodes".equals(exchange.getRequestURI().getPath()))) {
            respond(exchange, 404, Map.of("error", "not found"));
            return;
        }
        var resource = getClass().getResourceAsStream("/soc/index.html");
        if (resource == null) {
            respond(exchange, 404, Map.of("error", "console unavailable"));
            return;
        }
        byte[] body = resource.readAllBytes();
        exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
        exchange.sendResponseHeaders(200, body.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(body);
        }
    }

    private Map<String, Object> status() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("status", "RUNNING");
        result.put("nodeId", System.getProperty("sentinelx.nodeId", "UNKNOWN"));
        result.put("uptimeSeconds", Math.max(0, Instant.now().getEpochSecond() - startedAt.getEpochSecond()));
        result.put("version", "1.0.0");
        result.put("javaVersion", System.getProperty("java.version"));
        result.put("databaseStatus", "UP");
        result.put("tlsEnabled", tlsEnabled);
        result.put("activeConnections", metrics.activeConnections.get());
        result.put("queueDepth", metrics.queueSize.get());
        return result;
    }

    private Map<String, Object> time() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("timestampUtc", Instant.now().toString());
        result.put("source", "SYSTEM_CLOCK");
        result.put("synchronization", "chrony/NTP verified on this host");
        result.put("timezone", java.time.ZoneId.systemDefault().toString());
        result.put("authoritativeNode1", "UNVERIFIED");
        result.put("node1OffsetMillis", null);
        return result;
    }

    private Map<String, Object> networkStatus() {
        if (flowCollector != null) {
            Map<String, Object> capture = flowCollector.snapshot();
            if (Boolean.TRUE.equals(capture.get("available")))
                return capture;
            if ("PCAP".equals(capture.get("captureMode")))
                return capture;
            if (network != null) {
                Map<String, Object> telemetry = network.snapshot();
                if (Boolean.TRUE.equals(telemetry.get("available")))
                    return telemetry;
            }
            return capture;
        }
        if (network != null)
            return network.snapshot();
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("available", false);
        result.put("status", "NOT_CONFIGURED");
        result.put("message", "Network telemetry source not configured");
        result.put("source", "Not available");
        return result;
    }

    private Map<String, Object> networkMetrics() {
        Map<String, Object> result = new LinkedHashMap<>(networkStatus());
        result.remove("flows");
        return result;
    }

    private List<?> networkFlows() {
        Object flows = networkStatus().get("flows");
        return flows instanceof List<?> values ? values : List.of();
    }

    private Map<String, Object> metrics() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("eventsReceived", metrics.eventsReceived.sum());
        result.put("eventsProcessed", metrics.eventsProcessed.sum());
        result.put("eventsPersisted", metrics.eventsPersisted.sum());
        result.put("eventsDropped", metrics.eventsDropped.sum());
        result.put("alertsGenerated", metrics.alertsGenerated.sum());
        result.put("incidentsGenerated", metrics.incidentsGenerated.sum());
        result.put("ruleErrors", metrics.ruleErrors.sum());
        result.put("activeConnections", metrics.activeConnections.get());
        result.put("queueDepth", metrics.queueSize.get());
        result.put("queueHighWaterMark", metrics.queueHighWaterMark.get());
        return result;
    }

    private List<Map<String, Object>> events(Map<String, String> query) throws Exception {
        int page = positive(query.get("page"), 1), size = bounded(query.get("size"), 50, 100);
        StringBuilder sql = new StringBuilder(
                "SELECT event_id,timestamp,created_at,hostname,agent_id,log_level,source,message,source_ip,destination_ip,username,event_type FROM events WHERE 1=1");
        List<Object> args = new ArrayList<>();
        filter(sql, args, query, "hostname", "hostname");
        filter(sql, args, query, "logLevel", "log_level");
        filter(sql, args, query, "source", "source");
        if (query.containsKey("q")) {
            sql.append(" AND message LIKE ?");
            args.add("%" + query.get("q") + "%");
        }
        sql.append(" ORDER BY timestamp DESC LIMIT ? OFFSET ?");
        args.add(size);
        args.add((page - 1) * size);
        return rows(sql.toString(), args, List.of("eventId", "timestamp", "createdAt", "hostname", "agentId",
                "logLevel", "source", "message", "sourceIp", "destinationIp", "username", "eventType"));
    }

    private List<Map<String, Object>> alerts(Map<String, String> query) throws Exception {
        return rows(
                "SELECT severity,rule_id,hostname,first_seen,last_seen,occurrences,status FROM alerts ORDER BY CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 ELSE 1 END DESC,last_seen DESC LIMIT ? OFFSET ?",
                List.of(bounded(query.get("size"), 50, 100),
                        (positive(query.get("page"), 1) - 1) * bounded(query.get("size"), 50, 100)),
                List.of("severity", "ruleId", "hostname", "firstSeen", "lastSeen", "occurrences", "status"));
    }

    private List<Map<String, Object>> incidents(Map<String, String> query) throws Exception {
        String filter = query.get("status");
        if (filter != null && !List.of("OPEN", "ACKNOWLEDGED", "RESOLVED").contains(filter))
            throw new IllegalArgumentException("invalid incident status");
        String sql = "SELECT i.incident_id,i.severity,i.title,i.description,i.created_at,i.updated_at,i.resolved_at,i.status,i.response_action,(SELECT count(*) FROM incident_alerts a WHERE a.incident_id=i.incident_id) alert_count FROM incidents i"
                + (filter == null ? "" : " WHERE i.status=?") + " ORDER BY i.created_at DESC LIMIT ? OFFSET ?";
        List<Object> args = new ArrayList<>();
        if (filter != null)
            args.add(filter);
        int size = bounded(query.get("size"), 50, 100);
        args.add(size);
        args.add((positive(query.get("page"), 1) - 1) * size);
        return rows(sql, args, List.of("incidentId", "severity", "title", "description", "createdAt", "updatedAt",
                "resolvedAt", "status", "responseAction", "alertCount"));
    }

    private Map<String, Object> incident(String value) throws Exception {
        UUID id;
        try {
            id = UUID.fromString(value);
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("invalid incident id");
        }
        synchronized (database.writeLock()) {
            try (var statement = database.connection().prepareStatement(
                    "SELECT incident_id,created_at,updated_at,resolved_at,severity,title,description,status,response_action FROM incidents WHERE incident_id=?")) {
                statement.setString(1, id.toString());
                try (var result = statement.executeQuery()) {
                    if (!result.next())
                        throw new IllegalArgumentException("incident not found");
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("incidentId", result.getString(1));
                    item.put("createdAt", result.getString(2));
                    item.put("updatedAt", result.getString(3));
                    item.put("resolvedAt", result.getString(4));
                    item.put("severity", result.getString(5));
                    item.put("title", result.getString(6));
                    item.put("description", result.getString(7));
                    item.put("status", result.getString(8));
                    item.put("responseAction", result.getString(9));
                    item.put("alerts", incidentAlerts(id));
                    item.put("timeline", timeline(result.getString(2), result.getString(3), result.getString(4),
                            result.getString(9)));
                    return item;
                }
            }
        }
    }

    private List<Map<String, Object>> incidentAlerts(UUID id) throws Exception {
        try (var statement = database.connection().prepareStatement(
                "SELECT a.alert_id,a.rule_id,a.severity,a.hostname,a.first_seen,a.last_seen,a.occurrences,a.status FROM incident_alerts ia JOIN alerts a ON a.alert_id=ia.alert_id WHERE ia.incident_id=? ORDER BY a.last_seen DESC")) {
            statement.setString(1, id.toString());
            try (var result = statement.executeQuery()) {
                List<Map<String, Object>> items = new ArrayList<>();
                while (result.next()) {
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("alertId", result.getString(1));
                    item.put("ruleId", result.getString(2));
                    item.put("severity", result.getString(3));
                    item.put("hostname", result.getString(4));
                    item.put("firstSeen", result.getString(5));
                    item.put("lastSeen", result.getString(6));
                    item.put("occurrences", result.getLong(7));
                    item.put("status", result.getString(8));
                    items.add(item);
                }
                return items;
            }
        }
    }

    private List<Map<String, Object>> timeline(String created, String updated, String resolved, String action) {
        List<Map<String, Object>> items = new ArrayList<>();
        items.add(Map.of("event", "created", "timestamp", created));
        items.add(Map.of("event", "alert generated", "timestamp", created));
        if (action != null)
            items.add(Map.of("event", "response action", "timestamp", updated == null ? created : updated, "action",
                    action));
        if (resolved != null)
            items.add(Map.of("event", "resolved", "timestamp", resolved));
        return items;
    }

    private List<Map<String, Object>> nodes() throws Exception {
        synchronized (database.writeLock()) {
            try (var statement = database.connection().createStatement();
                    var result = statement.executeQuery(
                            "SELECT agent_id,hostname,max(timestamp) FROM events GROUP BY agent_id,hostname ORDER BY agent_id")) {
                List<Map<String, Object>> items = new ArrayList<>();
                while (result.next()) {
                    String lastSeen = result.getString(3);
                    boolean online = Duration.between(Instant.parse(lastSeen), Instant.now()).getSeconds() <= 30;
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("agentId", result.getString(1));
                    item.put("hostname", result.getString(2));
                    item.put("status", online ? "ONLINE" : "OFFLINE");
                    item.put("lastSeen", lastSeen);
                    item.put("eventsReceived", 0);
                    item.put("eventsDropped", 0);
                    item.put("connectionStatus", online ? "ONLINE" : "OFFLINE");
                    items.add(item);
                }
                return items;
            }
        }
    }

    private List<Map<String, Object>> rules() {
        return rules.stream().map(rule -> Map.<String, Object>of("ruleId", rule.getId(), "name", rule.getName(),
                "severity", rule.getSeverity().name())).collect(Collectors.toList());
    }

    private List<Map<String, Object>> rows(String sql, List<Object> args, List<String> names) throws Exception {
        synchronized (database.writeLock()) {
            try (var statement = database.connection().prepareStatement(sql)) {
                for (int i = 0; i < args.size(); i++)
                    statement.setObject(i + 1, args.get(i));
                try (var result = statement.executeQuery()) {
                    List<Map<String, Object>> items = new ArrayList<>();
                    while (result.next()) {
                        Map<String, Object> item = new LinkedHashMap<>();
                        for (int i = 0; i < names.size(); i++)
                            item.put(names.get(i), result.getObject(i + 1));
                        items.add(item);
                    }
                    return items;
                }
            }
        }
    }

    private static void filter(StringBuilder sql, List<Object> args, Map<String, String> query, String key,
            String column) {
        if (query.containsKey(key)) {
            sql.append(" AND ").append(column).append("=?");
            args.add(query.get(key));
        }
    }

    private static int positive(String value, int fallback) {
        int result = bounded(value, fallback, Integer.MAX_VALUE);
        if (result < 1)
            throw new IllegalArgumentException("page must be positive");
        return result;
    }

    private static int bounded(String value, int fallback, int max) {
        if (value == null)
            return fallback;
        try {
            int result = Integer.parseInt(value);
            if (result < 1 || result > max)
                throw new IllegalArgumentException("pagination value out of range");
            return result;
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException("pagination value must be numeric");
        }
    }

    private static Map<String, String> query(URI uri) {
        Map<String, String> values = new LinkedHashMap<>();
        if (uri.getRawQuery() == null)
            return values;
        for (String pair : uri.getRawQuery().split("&")) {
            String[] parts = pair.split("=", 2);
            if (parts.length == 2)
                values.put(java.net.URLDecoder.decode(parts[0], StandardCharsets.UTF_8),
                        java.net.URLDecoder.decode(parts[1], StandardCharsets.UTF_8));
        }
        return values;
    }

    private static void respond(HttpExchange exchange, int status, Object value) throws IOException {
        byte[] body = JsonUtil.write(value).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(status, body.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(body);
        }
    }

    @Override
    public void close() {
        server.stop(0);
        executor.shutdown();
    }
}
