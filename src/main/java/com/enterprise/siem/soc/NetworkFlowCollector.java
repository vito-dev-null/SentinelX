package com.enterprise.siem.soc;

import com.enterprise.siem.database.NetworkFlowRepository;
import com.enterprise.siem.model.NetworkFlow;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV6CommonPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.EOFException;
import java.time.Instant;
import java.util.UUID;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Independent metadata-only packet collector. It never reads application
 * payloads.
 */
public final class NetworkFlowCollector implements AutoCloseable {
    private static final Logger log = LoggerFactory.getLogger(NetworkFlowCollector.class);
    private static final int SNAPSHOT_LENGTH = 100;
    private static final String PCAP4J_VERSION = "2.0.0-alpha.6";
    private final NetworkFlowRepository repository;
    private final boolean enabled;
    private final String configuredInterface;
    private final int flowTimeoutSeconds;
    private final int retentionDays;
    private final int metricsIntervalSeconds;
    private final String captureMode;
    private final AtomicLong observedPackets = new AtomicLong();
    private final AtomicLong observedBytes = new AtomicLong();
    private volatile Instant lastPacket;
    private volatile long previousObservedPackets;
    private volatile long previousObservedBytes;
    private final Map<FlowKey, MutableFlow> flows = new ConcurrentHashMap<>();
    private final AtomicReference<Map<String, Object>> snapshot;
    private final ScheduledExecutorService executor = Executors.newScheduledThreadPool(2);
    private volatile boolean running;
    private volatile PcapHandle handle;
    private volatile long previousNewFlows;

    public NetworkFlowCollector(NetworkFlowRepository repository, boolean enabled, String configuredInterface,
            int flowTimeoutSeconds, int retentionDays, int metricsIntervalSeconds) {
        this(repository, enabled, configuredInterface, "INTERFACE", flowTimeoutSeconds, retentionDays,
                metricsIntervalSeconds);
    }

    public NetworkFlowCollector(NetworkFlowRepository repository, boolean enabled, String configuredInterface,
            String captureMode,
            int flowTimeoutSeconds, int retentionDays, int metricsIntervalSeconds) {
        if (flowTimeoutSeconds < 1 || retentionDays < 1 || metricsIntervalSeconds < 1)
            throw new IllegalArgumentException("network collector settings must be positive");
        this.repository = repository;
        this.enabled = enabled;
        this.configuredInterface = configuredInterface == null ? "" : configuredInterface.trim();
        this.captureMode = captureMode == null || captureMode.isBlank() ? "INTERFACE"
                : captureMode.trim().toUpperCase();
        this.snapshot = new AtomicReference<>(unavailable("Network flow capture is not started"));
        this.flowTimeoutSeconds = flowTimeoutSeconds;
        this.retentionDays = retentionDays;
        this.metricsIntervalSeconds = metricsIntervalSeconds;
    }

    public void start() {
        if (!enabled) {
            snapshot.set(unavailable("Network flow capture is disabled"));
            return;
        }
        Map<String, Object> startupTest = captureTest();
        snapshot.updateAndGet(previous -> withDiagnostics(previous, startupTest));
        running = true;
        executor.submit(this::captureLoop);
        executor.scheduleAtFixedRate(this::publishSnapshot, metricsIntervalSeconds, metricsIntervalSeconds,
                TimeUnit.SECONDS);
    }

    public Map<String, Object> snapshot() {
        return snapshot.get();
    }

    public Map<String, Object> captureTest() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("interface", configuredInterface);
        result.put("libpcapVersion", Pcaps.libVersion());
        result.put("pcap4jVersion", PCAP4J_VERSION);
        result.put("effectiveUid", effectiveUid());
        result.put("effectiveCapabilities", effectiveCapabilities());
        result.put("capabilityStatus", hasEffectiveCapability(13) ? "CAPABILITY_PRESENT" : "PERMISSION_DENIED");
        result.put("captureOpenResult", "CAPTURE_OPEN_FAILED");
        result.put("packetReceivedResult", "NO_TRAFFIC");
        try {
            PcapNetworkInterface networkInterface = findInterface();
            if (networkInterface == null) {
                result.put("captureOpenResult", "NO_INTERFACE");
                result.put("errorReason", "Configured capture interface is not available");
                return result;
            }
            result.put("interface", networkInterface.getName());
            PcapHandle testHandle = networkInterface.openLive(65535,
                    PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 1000);
            result.put("captureOpenResult", "CAPTURE_OPEN_SUCCESS");
            try {
                var packet = testHandle.getNextPacketEx();
                result.put("packetReceivedResult", "PACKET_RECEIVED");
                result.put("lastPacketTimestamp", packet.getTimestamp());
            } catch (TimeoutException exception) {
                result.put("packetReceivedResult", "NO_TRAFFIC");
                result.put("errorReason", "Capture handle opened but no packet arrived during self-test");
            } finally {
                testHandle.close();
            }
        } catch (PcapNativeException | IllegalStateException | SecurityException exception) {
            result.put("captureOpenResult", isPermissionFailure(exception.getMessage())
                    ? "PERMISSION_DENIED"
                    : "CAPTURE_OPEN_FAILED");
            result.put("errorReason", exception.getMessage());
        } catch (NotOpenException | EOFException exception) {
            result.put("captureOpenResult", "CAPTURE_OPEN_FAILED");
            result.put("errorReason", exception.getMessage());
        }
        return result;
    }

    private void captureLoop() {
        try {
            PcapNetworkInterface networkInterface = findInterface();
            if (networkInterface == null) {
                snapshot.set(unavailable("Configured capture interface is not available"));
                return;
            }
            handle = networkInterface.openLive(65535, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 1000);
            snapshot.updateAndGet(previous -> with(previous, "interface", networkInterface.getName()));
            while (running) {
                try {
                    var packet = handle.getNextPacketEx();
                    observe(packet, networkInterface.getName());
                } catch (TimeoutException ignored) {
                } catch (EOFException | NotOpenException exception) {
                    break;
                }
            }
        } catch (PcapNativeException | IllegalStateException exception) {
            snapshot.set(unavailable(captureFailureReason(exception.getMessage())));
            log.warn("Network packet capture unavailable on {}: {}", configuredInterface, exception.getMessage(),
                    exception);
        } finally {
            PcapHandle current = handle;
            if (current != null)
                current.close();
        }
    }

    private void observe(Packet packet, String interfaceName) {
        lastPacket = packet instanceof org.pcap4j.core.PcapPacket captured ? captured.getTimestamp() : Instant.now();
        observedPackets.incrementAndGet();
        observedBytes.addAndGet(packet.length());
        IpV4Packet ip = packet.get(IpV4Packet.class);
        IpV6Packet ipV6 = packet.get(IpV6Packet.class);
        if (ip == null && ipV6 == null)
            return;
        String source = ip != null ? ip.getHeader().getSrcAddr().getHostAddress()
                : ipV6.getHeader().getSrcAddr().getHostAddress();
        String destination = ip != null ? ip.getHeader().getDstAddr().getHostAddress()
                : ipV6.getHeader().getDstAddr().getHostAddress();
        String protocol;
        Integer sourcePort = null;
        Integer destinationPort = null;
        String tcpFlags = null;
        if (packet.contains(TcpPacket.class)) {
            protocol = "TCP";
            var header = packet.get(TcpPacket.class).getHeader();
            sourcePort = header.getSrcPort().valueAsInt();
            destinationPort = header.getDstPort().valueAsInt();
            List<String> flags = new ArrayList<>();
            if (header.getSyn())
                flags.add("SYN");
            if (header.getAck())
                flags.add("ACK");
            if (header.getRst())
                flags.add("RST");
            if (header.getFin())
                flags.add("FIN");
            if (header.getPsh())
                flags.add("PSH");
            if (header.getUrg())
                flags.add("URG");
            tcpFlags = flags.isEmpty() ? "NONE" : String.join(",", flags);
        } else if (packet.contains(UdpPacket.class)) {
            protocol = "UDP";
            var header = packet.get(UdpPacket.class).getHeader();
            sourcePort = header.getSrcPort().valueAsInt();
            destinationPort = header.getDstPort().valueAsInt();
        } else if (packet.contains(IcmpV4CommonPacket.class) || packet.contains(IcmpV6CommonPacket.class)) {
            protocol = "ICMP";
        } else {
            protocol = ip != null ? ip.getHeader().getProtocol().toString()
                    : ipV6.getHeader().getNextHeader().toString();
        }
        Instant timestamp = lastPacket;
        FlowKey key = new FlowKey(source, destination, sourcePort, destinationPort, protocol);
        flows.computeIfAbsent(key, ignored -> new MutableFlow(timestamp, key, interfaceName, packet)).observe(timestamp,
                packet.length(), tcpFlags);
    }

    private void publishSnapshot() {
        if (handle == null || !handle.isOpen()) {
            if ("Network flow capture is not started".equals(snapshot.get().get("reason"))) {
                snapshot.set(unavailable(captureFailureReason("raw socket could not be opened")));
            }
            return;
        }
        Instant now = Instant.now();
        List<NetworkFlow> current = flows.values().stream().map(MutableFlow::toFlow)
                .sorted(Comparator.comparing(NetworkFlow::lastSeen).reversed()).toList();
        List<NetworkFlow> expired = current.stream()
                .filter(flow -> flow.lastSeen().plusSeconds(flowTimeoutSeconds).isBefore(now)).toList();
        expired.forEach(flow -> flows.remove(new FlowKey(flow.sourceIp(), flow.destinationIp(), flow.sourcePort(),
                flow.destinationPort(), flow.protocol())));
        long newFlows = current.stream()
                .filter(flow -> flow.firstSeen().plusSeconds(metricsIntervalSeconds).isAfter(now)).count();
        long packetTotal = observedPackets.get();
        long byteTotal = observedBytes.get();
        long packetDelta = rate(packetTotal, previousObservedPackets);
        long byteDelta = rate(byteTotal, previousObservedBytes);
        try {
            repository.saveBatch(current, retentionDays);
            if (packetDelta > 0 || byteDelta > 0)
                repository.saveMetric(now, packetDelta, byteDelta, current.size(), newFlows, retentionDays);
        } catch (Exception exception) {
            log.warn("Network flow batch persistence failed: {}", exception.getMessage());
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("sensorType", "NETWORK_SENSOR");
        result.put("independentOfEndpoints", true);
        result.put("available", handle != null && handle.isOpen());
        result.put("status", handle != null && handle.isOpen() ? "LIVE" : "UNKNOWN");
        String activeInterface = current.isEmpty() ? (String) snapshot.get().get("interface")
                : current.get(0).interfaceName();
        result.put("interface", activeInterface);
        result.put("captureSource", "Pcap4J/libpcap");
        result.put("captureMode", captureMode);
        result.put("captureScope", captureScope());
        result.put("lastPacket", lastPacket == null ? null : lastPacket.toString());
        result.put("packetsPerSecond", packetDelta);
        result.put("bytesPerSecond", byteDelta);
        result.put("receivedPackets", packetTotal);
        result.put("receivedBytes", byteTotal);
        result.put("transmittedPackets", interfaceCounter(activeInterface, 9));
        result.put("transmittedBytes", interfaceCounter(activeInterface, 8));
        result.put("activeFlows", current.size());
        result.put("newFlowsPerSecond", rate(newFlows, previousNewFlows));
        result.put("tcpConnections", count(current, "TCP"));
        result.put("udpFlows", count(current, "UDP"));
        result.put("icmp", count(current, "ICMP"));
        result.put("topSources", aggregate(current, true, false));
        result.put("topDestinations", aggregate(current, false, false));
        result.put("topPorts", aggregate(current, false, true));
        result.put("topProtocols", aggregateProtocols(current));
        result.put("flows", current.stream().limit(SNAPSHOT_LENGTH).map(NetworkFlowCollector::flowView).toList());
        result.put("note", "Observed packet metadata only; visibility is limited to the configured capture interface.");
        previousObservedPackets = packetTotal;
        previousObservedBytes = byteTotal;
        previousNewFlows = newFlows;
        snapshot.set(result);
    }

    private PcapNetworkInterface findInterface() throws PcapNativeException {
        List<PcapNetworkInterface> devices = Pcaps.findAllDevs();
        if (!configuredInterface.isBlank() && !configuredInterface.equalsIgnoreCase("auto")) {
            return devices.stream().filter(networkInterface -> configuredInterface.equals(networkInterface.getName()))
                    .findFirst().orElse(null);
        }
        return devices.stream().filter(networkInterface -> networkInterface.isUp() && !networkInterface.isLoopBack())
                .findFirst().orElse(null);
    }

    private static long rate(long current, long previous) {
        return Math.max(0, current - previous);
    }

    private static Long interfaceCounter(String interfaceName, int field) {
        if (interfaceName == null || interfaceName.isBlank())
            return null;
        try {
            for (String line : java.nio.file.Files.readAllLines(java.nio.file.Path.of("/proc/net/dev"))) {
                int separator = line.indexOf(':');
                if (separator < 0 || !interfaceName.equals(line.substring(0, separator).trim()))
                    continue;
                String[] values = line.substring(separator + 1).trim().split("\\s+");
                return values.length > field ? Long.valueOf(values[field]) : null;
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private static String captureFailureReason(String detail) {
        if (!hasEffectiveCapability(13))
            return "PERMISSION_DENIED: CAP_NET_RAW missing";
        return detail == null || detail.isBlank()
                ? "CAPTURE_OPEN_FAILED: CAP_NET_RAW present; raw socket denied by host or container policy"
                : "CAPTURE_OPEN_FAILED: CAP_NET_RAW present; raw socket unavailable: " + detail;
    }

    private static boolean isPermissionFailure(String detail) {
        if (detail == null)
            return !hasEffectiveCapability(13);
        String normalized = detail.toLowerCase();
        return normalized.contains("permission") || normalized.contains("operation not permitted")
                || normalized.contains("access denied");
    }

    private static boolean hasEffectiveCapability(int bit) {
        try {
            for (String line : java.nio.file.Files.readAllLines(java.nio.file.Path.of("/proc/self/status"))) {
                if (line.startsWith("CapEff:")) {
                    long effective = Long.parseUnsignedLong(line.substring("CapEff:".length()).trim(), 16);
                    return (effective & (1L << bit)) != 0;
                }
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    private static String effectiveUid() {
        try {
            for (String line : java.nio.file.Files.readAllLines(java.nio.file.Path.of("/proc/self/status")))
                if (line.startsWith("Uid:"))
                    return line.trim();
        } catch (Exception ignored) {
        }
        return "UNKNOWN";
    }

    private static String effectiveCapabilities() {
        try {
            for (String line : java.nio.file.Files.readAllLines(java.nio.file.Path.of("/proc/self/status")))
                if (line.startsWith("CapEff:"))
                    return line.trim();
        } catch (Exception ignored) {
        }
        return "UNKNOWN";
    }

    private static long count(List<NetworkFlow> values, String protocol) {
        return values.stream().filter(flow -> protocol.equals(flow.protocol())).count();
    }

    private static List<Map<String, Object>> aggregate(List<NetworkFlow> values, boolean source, boolean ports) {
        Map<String, long[]> totals = new LinkedHashMap<>();
        for (NetworkFlow flow : values) {
            String key = ports ? String.valueOf(flow.destinationPort())
                    : source ? flow.sourceIp() : flow.destinationIp();
            if (key.equals("null"))
                continue;
            long[] total = totals.computeIfAbsent(key, ignored -> new long[2]);
            total[0] += flow.packets();
            total[1] += flow.bytes();
        }
        return totals.entrySet().stream().sorted((left, right) -> Long.compare(right.getValue()[1], left.getValue()[1]))
                .limit(10).map(entry -> {
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put(ports ? "port" : source ? "sourceIp" : "destinationIp", entry.getKey());
                    item.put("packets", entry.getValue()[0]);
                    item.put("bytes", entry.getValue()[1]);
                    item.put("flows",
                            values.stream()
                                    .filter(flow -> (ports ? String.valueOf(flow.destinationPort())
                                            : source ? flow.sourceIp() : flow.destinationIp()).equals(entry.getKey()))
                                    .count());
                    return item;
                }).toList();
    }

    private static List<Map<String, Object>> aggregateProtocols(List<NetworkFlow> values) {
        return values.stream().collect(java.util.stream.Collectors.groupingBy(NetworkFlow::protocol, LinkedHashMap::new,
                java.util.stream.Collectors.counting())).entrySet().stream().map(entry -> {
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("protocol", entry.getKey());
                    item.put("flows", entry.getValue());
                    return item;
                }).toList();
    }

    private static Map<String, Object> flowView(NetworkFlow flow) {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("flowId", flow.flowId().toString());
        value.put("firstSeen", flow.firstSeen());
        value.put("lastSeen", flow.lastSeen());
        value.put("sourceIp", flow.sourceIp());
        value.put("destinationIp", flow.destinationIp());
        value.put("sourcePort", flow.sourcePort());
        value.put("destinationPort", flow.destinationPort());
        value.put("protocol", flow.protocol());
        value.put("tcpFlags", flow.tcpFlags());
        value.put("packets", flow.packets());
        value.put("bytes", flow.bytes());
        value.put("packetsPerSecond", flow.packetsPerSecond());
        value.put("bytesPerSecond", flow.bytesPerSecond());
        value.put("durationMillis", flow.durationMillis());
        value.put("interface", flow.interfaceName());
        value.put("direction", flow.direction());
        value.put("sourceMac", flow.sourceMac());
        value.put("destinationMac", flow.destinationMac());
        value.put("vlan", flow.vlan());
        value.put("status", "OBSERVED");
        return value;
    }

    private Map<String, Object> unavailable(String message) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("sensorType", "NETWORK_SENSOR");
        result.put("independentOfEndpoints", true);
        result.put("available", false);
        result.put("status", "UNKNOWN");
        result.put("interface", configuredInterface.isBlank() ? "N/A" : configuredInterface);
        result.put("captureSource", "Pcap4J/libpcap");
        result.put("capture", "UNAVAILABLE");
        result.put("reason", message);
        result.put("captureMode", captureMode);
        result.put("captureScope", captureScope());
        result.put("lastPacket", "N/A");
        result.put("packetsPerSecond", "N/A");
        result.put("bytesPerSecond", "N/A");
        result.put("activeFlows", "N/A");
        result.put("newFlowsPerSecond", "N/A");
        result.put("tcpConnections", "N/A");
        result.put("udpFlows", "N/A");
        result.put("icmp", "N/A");
        result.put("flows", List.of());
        result.put("message", message);
        result.put("visibility", "N/A");
        return result;
    }

    private String captureScope() {
        return captureMode.equals("SPAN") || captureMode.equals("MIRROR") ? "SPAN/MIRROR"
                : captureMode.equals("TAP") ? "TAP" : captureMode.equals("GATEWAY") ? "GATEWAY" : "LOCAL INTERFACE";
    }

    private static Map<String, Object> with(Map<String, Object> source, String key, Object value) {
        Map<String, Object> copy = new LinkedHashMap<>(source);
        copy.put(key, value);
        return copy;
    }

    private static Map<String, Object> withDiagnostics(Map<String, Object> source, Map<String, Object> diagnostics) {
        Map<String, Object> copy = new LinkedHashMap<>(source);
        copy.put("captureOpenResult", diagnostics.get("captureOpenResult"));
        copy.put("packetReceivedResult", diagnostics.get("packetReceivedResult"));
        copy.put("capabilityStatus", diagnostics.get("capabilityStatus"));
        copy.put("libpcapVersion", diagnostics.get("libpcapVersion"));
        copy.put("pcap4jVersion", diagnostics.get("pcap4jVersion"));
        copy.put("effectiveUid", diagnostics.get("effectiveUid"));
        copy.put("effectiveCapabilities", diagnostics.get("effectiveCapabilities"));
        copy.put("errorReason", diagnostics.get("errorReason"));
        copy.put("lastPacketTimestamp", diagnostics.get("lastPacketTimestamp"));
        return copy;
    }

    @Override
    public void close() {
        running = false;
        PcapHandle current = handle;
        if (current != null)
            current.close();
        executor.shutdownNow();
    }

    private record FlowKey(String sourceIp, String destinationIp, Integer sourcePort, Integer destinationPort,
            String protocol) {
    }

    private static final class MutableFlow {
        private final UUID flowId = UUID.randomUUID();
        private final FlowKey key;
        private final Instant firstSeen;
        private final String interfaceName;
        private final String sourceMac;
        private final String destinationMac;
        private final String vlan;
        private Instant lastSeen;
        private long packets;
        private long bytes;
        private String tcpFlags;

        private MutableFlow(Instant timestamp, FlowKey key, String interfaceName, Packet packet) {
            this.firstSeen = timestamp;
            this.lastSeen = timestamp;
            this.key = key;
            this.interfaceName = interfaceName;
            this.sourceMac = packet.contains(EthernetPacket.class)
                    ? packet.get(EthernetPacket.class).getHeader().getSrcAddr().toString()
                    : null;
            this.destinationMac = packet.contains(EthernetPacket.class)
                    ? packet.get(EthernetPacket.class).getHeader().getDstAddr().toString()
                    : null;
            this.vlan = null;
        }

        private synchronized void observe(Instant timestamp, int length, String tcpFlags) {
            lastSeen = timestamp;
            packets++;
            bytes += length;
            if (tcpFlags != null)
                this.tcpFlags = tcpFlags;
        }

        private synchronized NetworkFlow toFlow() {
            return new NetworkFlow(flowId, firstSeen, lastSeen, key.sourceIp(), key.destinationIp(), key.sourcePort(),
                    key.destinationPort(), key.protocol(), tcpFlags, packets, bytes, interfaceName, "N/A", sourceMac,
                    destinationMac, vlan);
        }
    }
}
