package com.enterprise.siem.model;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/** Metadata-only network flow aggregated from packets actually observed by the sensor. */
public record NetworkFlow(
        UUID flowId,
        Instant firstSeen,
        Instant lastSeen,
        String sourceIp,
        String destinationIp,
        Integer sourcePort,
        Integer destinationPort,
        String protocol,
        String tcpFlags,
        long packets,
        long bytes,
        String interfaceName,
        String direction,
        String sourceMac,
        String destinationMac,
        String vlan) {

    public NetworkFlow {
        flowId = flowId == null ? UUID.randomUUID() : flowId;
        if (firstSeen == null || lastSeen == null) throw new IllegalArgumentException("flow timestamps are required");
        if (lastSeen.isBefore(firstSeen)) throw new IllegalArgumentException("lastSeen must not precede firstSeen");
        if (packets < 1 || bytes < 0) throw new IllegalArgumentException("flow counters are invalid");
        protocol = protocol == null || protocol.isBlank() ? "UNKNOWN" : protocol;
        interfaceName = interfaceName == null || interfaceName.isBlank() ? "N/A" : interfaceName;
        direction = direction == null || direction.isBlank() ? "N/A" : direction;
    }

    public long durationMillis() { return Duration.between(firstSeen, lastSeen).toMillis(); }
    public double packetsPerSecond() { return packets / Math.max(1.0, durationMillis() / 1000.0); }
    public double bytesPerSecond() { return bytes / Math.max(1.0, durationMillis() / 1000.0); }
}
