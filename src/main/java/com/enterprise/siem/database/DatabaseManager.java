package com.enterprise.siem.database;
import java.nio.file.*; import java.sql.*;
public final class DatabaseManager implements AutoCloseable {
    private final Connection connection;
    public DatabaseManager(String path) throws SQLException { this(path, 5000, true); }
    public DatabaseManager(String path, long busyTimeoutMs, boolean walEnabled) throws SQLException {
        try {
            Path file = Path.of(path);
            if (file.getParent() != null) Files.createDirectories(file.getParent());
        } catch (java.io.IOException exception) {
            throw new SQLException("Cannot create database directory", exception);
        }
        if (busyTimeoutMs <= 0) throw new IllegalArgumentException("database.busyTimeoutMs must be positive");
        connection = DriverManager.getConnection("jdbc:sqlite:" + path);
        try (Statement statement = connection.createStatement()) {
            statement.executeUpdate("PRAGMA busy_timeout=" + busyTimeoutMs);
            if (walEnabled) statement.executeUpdate("PRAGMA journal_mode=WAL");
        }
        connection.setAutoCommit(false);
        initialize();
        connection.commit();
        connection.setAutoCommit(true);
    }
    private void initialize() throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.executeUpdate("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)");
            statement.executeUpdate("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT UNIQUE NOT NULL,timestamp TEXT NOT NULL,hostname TEXT NOT NULL,agent_id TEXT NOT NULL,log_level TEXT,source TEXT,message TEXT,source_ip TEXT,destination_ip TEXT,username TEXT,event_type TEXT,raw_json TEXT NOT NULL,created_at TEXT NOT NULL)");
            statement.executeUpdate("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)");
            statement.executeUpdate("CREATE INDEX IF NOT EXISTS idx_events_hostname ON events(hostname)");
            statement.executeUpdate("CREATE INDEX IF NOT EXISTS idx_events_agent ON events(agent_id)");
            statement.executeUpdate("CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip)");
            statement.executeUpdate("CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)");
            statement.executeUpdate("CREATE TABLE IF NOT EXISTS network_flows (flow_id TEXT PRIMARY KEY,first_seen TEXT NOT NULL,last_seen TEXT NOT NULL,source_ip TEXT,destination_ip TEXT,source_port INTEGER,destination_port INTEGER,protocol TEXT,tcp_flags TEXT,packets INTEGER NOT NULL,bytes INTEGER NOT NULL,interface_name TEXT,direction TEXT,source_mac TEXT,destination_mac TEXT,vlan TEXT,created_at TEXT NOT NULL)");
            statement.executeUpdate("CREATE INDEX IF NOT EXISTS idx_network_flows_last_seen ON network_flows(last_seen)");
            statement.executeUpdate("CREATE TABLE IF NOT EXISTS network_metrics (timestamp TEXT PRIMARY KEY,source TEXT NOT NULL,packets INTEGER NOT NULL,bytes INTEGER NOT NULL,active_flows INTEGER,new_flows INTEGER)");
            statement.executeUpdate("CREATE INDEX IF NOT EXISTS idx_network_metrics_timestamp ON network_metrics(timestamp)");
            statement.executeUpdate("CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY AUTOINCREMENT,alert_id TEXT UNIQUE,rule_id TEXT,timestamp TEXT,severity TEXT,hostname TEXT,source_ip TEXT,description TEXT,status TEXT,first_seen TEXT,last_seen TEXT,occurrences INTEGER NOT NULL DEFAULT 1)");
            try { statement.executeUpdate("ALTER TABLE alerts ADD COLUMN first_seen TEXT"); } catch (SQLException ignored) { }
            try { statement.executeUpdate("ALTER TABLE alerts ADD COLUMN last_seen TEXT"); } catch (SQLException ignored) { }
            try { statement.executeUpdate("ALTER TABLE alerts ADD COLUMN occurrences INTEGER NOT NULL DEFAULT 1"); } catch (SQLException ignored) { }
            statement.executeUpdate("CREATE INDEX IF NOT EXISTS idx_alerts_rule_source ON alerts(rule_id,source_ip,timestamp)");
            statement.executeUpdate("CREATE TABLE IF NOT EXISTS incidents (id INTEGER PRIMARY KEY AUTOINCREMENT,incident_id TEXT UNIQUE,created_at TEXT,severity TEXT,title TEXT,description TEXT,status TEXT,response_action TEXT,updated_at TEXT,resolved_at TEXT)");
            statement.executeUpdate("CREATE TABLE IF NOT EXISTS incident_alerts (incident_id TEXT NOT NULL,alert_id TEXT NOT NULL UNIQUE,linked_at TEXT NOT NULL)");
            statement.executeUpdate("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)");
            statement.executeUpdate("INSERT OR IGNORE INTO schema_version(version,applied_at) VALUES(1,datetime('now'))");
            try { statement.executeUpdate("ALTER TABLE incidents ADD COLUMN updated_at TEXT"); } catch (SQLException ignored) { }
            try { statement.executeUpdate("ALTER TABLE incidents ADD COLUMN resolved_at TEXT"); } catch (SQLException ignored) { }
            statement.executeUpdate("INSERT OR IGNORE INTO schema_version(version,applied_at) VALUES(2,datetime('now'))");
            statement.executeUpdate("PRAGMA user_version=2");
        }
    }
    public Object writeLock() { return connection; }
    public Connection connection() { return connection; } public void close() throws SQLException { connection.close(); }
}
