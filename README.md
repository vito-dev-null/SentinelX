# SentinelX Enterprise SIEM/SOC

SentinelX is a single Java 25 application for a three-node Linux security cluster. Nodes 1 and 2 tail local logs and send JSON Lines to Node 3. Node 1 also hosts the controller desktop and dispatches heavy workloads only to remote workers. Node 3 validates, queues, stores and detects events, then creates alerts, incidents and safe SOAR dry-run audit entries.

## Architecture

```text
Node 1 SecurityAgent --TLS/TCP JSON Lines--+
Node 2 SecurityAgent --TLS/TCP JSON Lines--+--> Node 3 EnterpriseSIEMServer
										   |       | bounded queue
										   |       +--> SQLite data/siem.db
										   |       +--> rules -> alerts -> incidents
										   |       `--> SOAR dry-run -> logs/security-audit.log
```

## Requirements and build

Requirements: JDK 25 and Maven 3.9+. The project does not upgrade or install Java. Build, test and package:

```sh
JAVA_HOME=/path/to/jdk-25 mvn clean verify
mvn clean package
```

The runnable shaded artifact is `target/enterprise-siem-1.0.0-shaded.jar`.

Maven must itself run on a JDK 25 installation. A Maven process running on JDK 17 cannot compile this project, even when a JDK 25 compiler exists elsewhere. Select JDK 25 through the shell, VS Code Java runtime, or a user-level Maven toolchain; do not put a machine-specific path in the project:

```sh
JAVA_HOME=/path/to/jdk-25 PATH="$JAVA_HOME/bin:$PATH" mvn clean verify
```

## Configuration and run

For a local controller, copy `config/server.properties.template` to `config/server.properties`; the host-specific file is ignored by Git and is the launcher's default config. Use `config/examples/node1.properties`, `node2.properties` and `node3.properties` as templates. Before starting agents, replace the reserved `.invalid` hostnames with the intended server and worker hostnames or Tailscale addresses. Configure `soc.host` to `127.0.0.1` for local-only access, or to the host's Tailscale interface address when peers need access; do not bind the unauthenticated SOC API to `0.0.0.0`. Start the central node with `java -jar target/enterprise-siem-1.0.0-shaded.jar server --config config/examples/node3.properties`; start an agent with `java -jar target/enterprise-siem-1.0.0-shaded.jar agent --config config/examples/node1.properties`.

`data/siem.db` is created automatically. Tables are `events`, `alerts`, and `incidents`, with indexes on timestamp, hostname, agent, source IP and event type. Raw event JSON is retained. Startup uses non-destructive `schema_version` migrations, configurable busy timeout and WAL.

## Rules, safety and SOAR

`config/rules.yaml` enables/disables SSH brute force, distributed brute force, traffic spike and suspicious login rules. Thresholds and windows are configurable without recompiling. Rules use bounded, thread-safe time windows and isolate failures. TCP readers enforce event size/rate/client limits; accepted events enter a bounded queue and overflow is measured. SOAR defaults to dry-run: critical incidents log `SIMULATE_ISOLATION`; no firewall changes are made. Only enum actions are accepted, never event text or IPs as commands.

TLS uses PKCS12 keystore/truststore files when `tls.enabled=true`; set `tls.requireClientAuth=true` on Node 3 for mTLS. Passwords are supplied through `SENTINELX_TLS_*_PASSWORD`, never committed. Certificates are validated normally, including hostname verification by the TLS socket. The server also checks that the event `agentId` matches the authenticated client certificate subject when mTLS is enabled.

Generate test material outside the repository with a private CA, a server certificate containing the server DNS name/IP in SAN, and one certificate per agent. Import the CA into the opposite truststore. Never commit private keys or real passwords.

## Run modes

```sh
java -jar target/enterprise-siem-1.0.0-shaded.jar server --config config/server.properties
java -jar target/enterprise-siem-1.0.0-shaded.jar agent --config config/agent.properties
java -jar target/enterprise-siem-1.0.0-shaded.jar status --config config/server.properties
```

Start Node 3 first, then Node 1/2. The Desktop launcher starts the server and opens the local SOC dashboard after its health endpoint is ready. `status` is local and reports persisted counts.

Node 1 runs as a controller with `node.role=CONTROLLER`. The controller process does not initialize the TCP server, SQLite database, or packet collector. Heavy workload classes (`BUILD`, `COMPILE`, `TEST_CPU`, `CPU_HEAVY`, `BACKGROUND`, `SERVICES`, `WORKERS`, `BATCH`) are remote-only and are dispatched only to `nodo2` or `nodo3`:

```sh
./sentinelx-cli dispatch BUILD build-2026-09-09
```

When no worker is available, the command prints `NO_WORKER_AVAILABLE` and exits with code `75`; it never executes the workload on Node 1. Configure the worker API endpoints with `worker.nodo2.url` and `worker.nodo3.url`. The desktop can use a healthy worker's read-only SOC dashboard, or start a local controller dashboard backend if all workers are offline; this local backend does not make Node 1 eligible for remote-only workload execution.

The desktop, CLI and agent launchers auto-detect workers before starting services. If `nodo2` or `nodo3` answers `/health`, they use REMOTE-FIRST mode and Node 1 starts no local server or packet collector. If both workers are unreachable, they use STANDALONE mode and start the local backend only on that explicit probe result. `./scripts/cluster-control.sh status` reports the three node states, the current mode, and worker load.

Cluster traffic uses Tailscale exclusively. Configure each worker with its Tailscale address or MagicDNS name. Keep the SOC API bound to `127.0.0.1` for local-only use; when peers need access, bind it to that host's Tailscale interface address rather than `0.0.0.0`, and restrict TCP ports 5050 and 8080 to the Tailscale interface in the host firewall. The checked-in configs use reserved `.invalid` hostnames as placeholders and will not reach real nodes until replaced. Node 1's desktop launcher requires a connected Tailscale daemon and never starts a local backend while Tailscale is disconnected; if Tailscale is unavailable, run `./scripts/tailscale-connect.sh` and complete `tailscale up` authentication. When Tailscale is connected but every worker is offline, Node 1 starts its local controller backend, which remains reachable on the tailnet address. The launcher uses a worker dashboard only after its health endpoint responds.

`SecurityAgent -> SIEMClient -> EnterpriseSIEMServer -> bounded queue -> EventRepository -> RuleEngine -> AlertManager -> IncidentManager -> ResponseManager`. The server uses one virtual thread per connection and drains queued events during shutdown.

## SOC Console

The optional read-only SOC Console is served by the persistent headless collector/API process through the JDK HTTP server. The JavaFX desktop is only an embedded WebView client, so closing it does not stop packet capture; `sentinelx-cli` is another client of the same API. The collector opens the configured interface through Pcap4J/libpcap and exposes `/api/status`, `/api/metrics`, `/api/capture-test`, `/api/events`, `/api/alerts`, `/api/incidents`, `/api/nodes` and `/api/rules`. Enable it with `soc.enabled=true` and choose `soc.port`; open `http://127.0.0.1:8080/dashboard` after starting the server. The first version has no response endpoints and no improvised authentication: place it behind the enterprise identity and authorization boundary before exposing it beyond a trusted host.

## Validation and safety

Every network line is bounded, parsed by Jackson and validated before persistence. SQLite writes use prepared statements and serialized repository access. Invalid input is rejected without disconnecting other agents. ProcessExecutor accepts only the `ResponseAction` enum and fails closed when real execution is requested. Application logs rotate daily and by size. Reference systemd units live under `deployment/` and are not installed automatically.

The correlation engine uses configurable bounded per-key state with global key limits, LRU eviction, TTL cleanup and eviction/drop counters. Application configuration rejects invalid numeric and boolean values and supports `SENTINELX_*` environment overrides. Development mode remains plain TCP with `tls.enabled=false`; production deployments should enable TLS and mTLS with test certificates generated outside the repository.
