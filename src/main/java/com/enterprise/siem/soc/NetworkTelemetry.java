package com.enterprise.siem.soc;

import java.io.IOException;
import java.net.NetworkInterface;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Reads operating-system interface counters; it does not synthesize flow data. */
public final class NetworkTelemetry {
    private final boolean enabled;
    private final String configuredInterface;
    private Reading previous;

    public NetworkTelemetry(boolean enabled, String configuredInterface) {
        this.enabled = enabled;
        this.configuredInterface = configuredInterface == null ? "" : configuredInterface.trim();
    }

    public synchronized Map<String, Object> snapshot() {
        if (!enabled) return unavailable("Network telemetry disabled");
        try {
            Map<String, Counter> counters = readCounters();
            String interfaceName = selectInterface(counters);
            Counter current = counters.get(interfaceName);
            if (current == null) return unavailable("Network interface not observed");
            Instant now = Instant.now();
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("sensorType", "NETWORK_SENSOR");
            result.put("independentOfEndpoints", true);
            result.put("available", true);
            result.put("status", "LIVE");
            result.put("source", "/proc/net/dev");
            result.put("interface", interfaceName);
            result.put("timestamp", now.toString());
            result.put("lastPacket", null);
            result.put("receivedBytes", current.receivedBytes());
            result.put("transmittedBytes", current.transmittedBytes());
            result.put("receivedPackets", current.receivedPackets());
            result.put("transmittedPackets", current.transmittedPackets());
            if (previous != null && previous.interfaceName().equals(interfaceName)) {
                long seconds = Math.max(1, (now.toEpochMilli() - previous.timestamp().toEpochMilli()) / 1000);
                result.put("bytesPerSecond", (current.totalBytes() - previous.counter().totalBytes()) / seconds);
                result.put("packetsPerSecond", (current.totalPackets() - previous.counter().totalPackets()) / seconds);
            } else {
                result.put("bytesPerSecond", null);
                result.put("packetsPerSecond", null);
            }
            result.put("activeConnections", null);
            result.put("topSources", null);
            result.put("topDestinations", null);
            result.put("topPorts", null);
            result.put("protocolDistribution", null);
            result.put("suspiciousTraffic", null);
            result.put("dosDdosDetection", null);
            result.put("note", "Independent interface counters only. Packet capture is not configured; traffic visibility depends on this sensor interface or a SPAN/TAP feed.");
            previous = new Reading(interfaceName, current, now);
            return result;
        } catch (IOException exception) {
            return unavailable("Network telemetry source unavailable");
        }
    }

    private Map<String, Counter> readCounters() throws IOException {
        Map<String, Counter> result = new LinkedHashMap<>();
        for (String line : Files.readAllLines(Path.of("/proc/net/dev"))) {
            int separator = line.indexOf(':');
            if (separator < 0) continue;
            String name = line.substring(0, separator).trim();
            String[] values = line.substring(separator + 1).trim().split("\\s+");
            if (values.length >= 9) result.put(name, new Counter(Long.parseLong(values[0]), Long.parseLong(values[1]), Long.parseLong(values[8]), Long.parseLong(values[9])));
        }
        return result;
    }

    private String selectInterface(Map<String, Counter> counters) {
        if (!configuredInterface.isBlank() && !configuredInterface.equalsIgnoreCase("auto")) return configuredInterface;
        try {
            var interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                var networkInterface = interfaces.nextElement();
                String name = networkInterface.getName();
                if (networkInterface.isUp() && !networkInterface.isLoopback() && !name.startsWith("tailscale") && counters.containsKey(name)) return name;
            }
        } catch (Exception ignored) { }
        return counters.keySet().stream().filter(name -> !name.equals("lo") && !name.startsWith("tailscale")).findFirst().orElse("");
    }

    private static Map<String, Object> unavailable(String message) {
        return Map.of("available", false, "status", "OFFLINE", "message", message, "source", "Not available");
    }

    private record Counter(long receivedBytes, long receivedPackets, long transmittedBytes, long transmittedPackets) {
        long totalBytes() { return receivedBytes + transmittedBytes; }
        long totalPackets() { return receivedPackets + transmittedPackets; }
    }

    private record Reading(String interfaceName, Counter counter, Instant timestamp) { }
}
