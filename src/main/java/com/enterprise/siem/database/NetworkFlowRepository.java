package com.enterprise.siem.database;

import com.enterprise.siem.model.NetworkFlow;

import java.sql.SQLException;
import java.time.Instant;
import java.util.Collection;

/** Persists metadata-only flows in batches so packet capture never writes per packet. */
public final class NetworkFlowRepository {
    private final DatabaseManager database;

    public NetworkFlowRepository(DatabaseManager database) { this.database = database; }

    public void saveBatch(Collection<NetworkFlow> flows, int retentionDays) throws SQLException {
        if (flows.isEmpty()) return;
        synchronized (database.writeLock()) {
            try (var statement = database.connection().prepareStatement("INSERT OR REPLACE INTO network_flows(flow_id,first_seen,last_seen,source_ip,destination_ip,source_port,destination_port,protocol,tcp_flags,packets,bytes,interface_name,direction,source_mac,destination_mac,vlan,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")) {
                for (NetworkFlow flow : flows) {
                    statement.setString(1, flow.flowId().toString());
                    statement.setString(2, flow.firstSeen().toString());
                    statement.setString(3, flow.lastSeen().toString());
                    statement.setString(4, flow.sourceIp());
                    statement.setString(5, flow.destinationIp());
                    if (flow.sourcePort() == null) statement.setObject(6, null); else statement.setInt(6, flow.sourcePort());
                    if (flow.destinationPort() == null) statement.setObject(7, null); else statement.setInt(7, flow.destinationPort());
                    statement.setString(8, flow.protocol());
                    statement.setString(9, flow.tcpFlags());
                    statement.setLong(10, flow.packets());
                    statement.setLong(11, flow.bytes());
                    statement.setString(12, flow.interfaceName());
                    statement.setString(13, flow.direction());
                    statement.setString(14, flow.sourceMac());
                    statement.setString(15, flow.destinationMac());
                    statement.setString(16, flow.vlan());
                    statement.setString(17, Instant.now().toString());
                    statement.addBatch();
                }
                statement.executeBatch();
            }
            try (var cleanup = database.connection().prepareStatement("DELETE FROM network_flows WHERE julianday(last_seen) < julianday('now', ?)")) {
                cleanup.setString(1, "-" + Math.max(1, retentionDays) + " days");
                cleanup.executeUpdate();
            }
        }
    }

    public void saveMetric(Instant timestamp, long packets, long bytes, long activeFlows, long newFlows, int retentionDays) throws SQLException {
        synchronized (database.writeLock()) {
            try (var statement = database.connection().prepareStatement("INSERT OR REPLACE INTO network_metrics(timestamp,source,packets,bytes,active_flows,new_flows) VALUES(?,?,?,?,?,?)")) {
                statement.setString(1, timestamp.toString()); statement.setString(2, "Pcap4J/libpcap"); statement.setLong(3, packets); statement.setLong(4, bytes); statement.setLong(5, activeFlows); statement.setLong(6, newFlows); statement.executeUpdate();
            }
            try (var cleanup = database.connection().prepareStatement("DELETE FROM network_metrics WHERE julianday(timestamp) < julianday('now', ?)")) {
                cleanup.setString(1, "-" + Math.max(1, retentionDays) + " days"); cleanup.executeUpdate();
            }
        }
    }
}