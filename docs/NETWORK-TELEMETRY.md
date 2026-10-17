# Network Telemetry Deployment

SentinelX runs the network collector in the server process. It reads counters from the configured host interface and does not depend on any agent or endpoint being online. Endpoint events are stored separately and their `LAST SEEN` status does not stop collection.

## Placement

For traffic visibility beyond the server host, place the collector on a dedicated monitoring host connected to:

- a switch mirror/SPAN port for the VLANs and uplinks that must be observed; or
- a network TAP, preferably at the aggregation point carrying the relevant traffic.

A bridge or inline placement is only appropriate when the operating model explicitly requires it; the collector must remain passive and must not become a forwarding dependency. Configure `network.interface` to the interface receiving that mirror/TAP feed. `auto` selects the first eligible non-loopback interface and is suitable only when that choice is unambiguous.

The collector can observe only traffic delivered to its interface. A single host interface does not provide complete network visibility, and `/proc/net/dev` exposes aggregate packet and byte counters, not packet headers or flows. Therefore IPs, ports, protocol distribution, TCP flags, connection state, top talkers, suspicious traffic, and DOS/DDOS detection remain `N/A` until a packet-capture collector is deployed at an appropriate observation point.

The dashboard labels this source `NETWORK SENSOR` and keeps it separate from `ENDPOINTS`. An endpoint can be `OFFLINE` while the network sensor remains `ONLINE`; no synthetic traffic is generated in either state.