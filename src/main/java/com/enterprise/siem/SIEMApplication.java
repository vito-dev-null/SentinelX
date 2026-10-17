package com.enterprise.siem;

import com.enterprise.siem.alert.*;
import com.enterprise.siem.agent.*;
import com.enterprise.siem.config.*;
import com.enterprise.siem.database.*;
import com.enterprise.siem.detection.*;
import com.enterprise.siem.incident.*;
import com.enterprise.siem.security.*;
import com.enterprise.siem.server.*;
import com.enterprise.siem.soar.*;
import com.enterprise.siem.util.*;
import com.enterprise.siem.desktop.DesktopApplication;
import java.util.*;
import java.io.IOException;
import com.enterprise.siem.cli.CliApplication;

public final class SIEMApplication {
	public static void main(String[] args) throws Exception {
		String mode = args.length > 0 ? args[0] : "server";
		if (mode.equals("agent")) {
			AppConfig config = new AppConfig(configPath(args, "config/agent.properties"));
			var tls = tls(config);
			String siemHost = System.getenv().getOrDefault("SENTINELX_SIEM_HOST",
					config.get("siem.host", "127.0.0.1"));
			try (var agent = new SecurityAgent(config.get("node.id", "agent"), siemHost,
					config.integer("siem.port", 5050), config.integer("server.maxEventSizeBytes", 65536), tls)) {
				agent.watch(List.of(config.get("log.files", "/var/log/auth.log").split(",")));
				Thread.currentThread().join();
			}
			return;
		}
		if (mode.equals("status")) {
			status(new AppConfig(configPath(args, "config/server.properties")));
			return;
		}
		if (mode.equals("cli")) {
			CliApplication.run(args);
			return;
		}
		if (mode.equals("desktop")) {
			AppConfig config = new AppConfig(configPath(args, "config/server.properties"));
			System.setProperty("sentinelx.nodeId", config.get("node.id", "UNKNOWN"));
			String appName = config.get("desktop.appName", config.get("node.id", "SentinelX"));
			String dashboardBase = System.getenv().getOrDefault("SENTINELX_SOC_URL", config.get("soc.remoteUrl",
					"http://127.0.0.1:" + config.integer("soc.port", 8080)));
			DesktopApplication.configure(dashboardBase + "/dashboard", () -> {
			}, appName);
			DesktopApplication.launchApplication();
			return;
		}
		if (!mode.equals("server"))
			throw new IllegalArgumentException("usage: server [--config path] | agent [--config path]");
		AppConfig config = new AppConfig(configPath(args, "config/server.properties"));
		boolean standaloneOverride = Boolean.parseBoolean(
				System.getenv().getOrDefault("SENTINELX_FORCE_STANDALONE", "false"));
		if ("CONTROLLER".equalsIgnoreCase(config.get("node.role", "WORKER")) && !standaloneOverride) {
			System.exit(com.enterprise.siem.dispatch.ControllerApplication.run(args, config));
			return;
		}
		System.setProperty("sentinelx.nodeId", config.get("node.id", "UNKNOWN"));
		try (DatabaseManager db = new DatabaseManager(config.get("database.path", "data/siem.db"),
				config.integer("database.busyTimeoutMs", 5000), config.bool("database.walEnabled", true))) {
			var metrics = new SIEMMetrics();
			var audit = new FileSecurityAuditLogger("logs/security-audit.log");
			var response = new ResponseManager(config.bool("soar.dryRun", true), new ProcessExecutor(), audit, metrics);
			var incidents = new IncidentManager(new IncidentRepository(db), response, metrics);
			var alerts = new AlertManager(new AlertRepository(db), incidents, metrics);
			var configuredRules = RuleConfigLoader.load(config.get("rules.path", "config/rules.yaml"));
			var rules = new RuleEngine(configuredRules, alerts::accept, metrics);
			var network = new com.enterprise.siem.soc.NetworkTelemetry(config.bool("network.enabled", true),
					config.get("network.interface", "auto"));
			var flowCollector = new com.enterprise.siem.soc.NetworkFlowCollector(new NetworkFlowRepository(db),
					config.bool("network.enabled", true), config.get("network.interface", "auto"),
					config.get("network.captureMode", "INTERFACE"), config.integer("network.flowTimeoutSeconds", 60),
					config.integer("network.retentionDays", 30), config.integer("network.metricsIntervalSeconds", 1));
				var serverBindAddress = java.net.InetAddress.getByName(config.get("server.host", "127.0.0.1"));
				var serverTls = tls(config);
				try (flowCollector;
						var server = new EnterpriseSIEMServer(config.integer("server.port", 5050), new EventRepository(db),
								rules, metrics, config.integer("server.maxConnections", 100),
								config.integer("server.maxEventsPerSecond", 5000),
								config.integer("server.maxEventSizeBytes", 65536), serverTls,
								config.integer("server.queueCapacity", 10000), serverBindAddress);
					var soc = config.bool("soc.enabled", true)
							? new com.enterprise.siem.soc.SocApiServer(config.get("soc.host", "127.0.0.1"),
									config.integer("soc.port", 8080), db, metrics, configuredRules,
									tls(config).enabled(), network, flowCollector)
							: null) {
				flowCollector.start();
				Runtime.getRuntime().addShutdownHook(new Thread(server::close));
				if (soc != null)
					soc.start();
				if (desktopMode(args)) {
					String appName = config.get("desktop.appName", config.get("node.id", "SentinelX 3"));
					DesktopApplication.configure("http://127.0.0.1:" + config.integer("soc.port", 8080) + "/dashboard",
							() -> {
								if (soc != null)
									soc.close();
								server.close();
							}, appName);
					Thread serverThread = new Thread(() -> {
						try {
							server.start();
						} catch (IOException exception) {
							throw new RuntimeException(exception);
						}
					}, "sentinelx-server");
					serverThread.start();
					DesktopApplication.launchApplication();
				} else
					server.start();
			}
		}
	}

	private static TlsConfiguration tls(AppConfig c) {
		return TlsConfiguration.from(c.get("tls.enabled", "false"),
				c.get("tls.keystore.path", c.get("tls.keystore", "")), c.get("tls.keystore.password", ""),
				c.get("tls.truststore.path", c.get("tls.truststore", "")), c.get("tls.truststore.password", ""),
				c.bool("tls.requireClientAuth", false));
	}

	private static void status(AppConfig config) throws Exception {
		try (var db = new DatabaseManager(config.get("database.path", "data/siem.db"),
				config.integer("database.busyTimeoutMs", 5000), config.bool("database.walEnabled", true));
				var statement = db.connection().createStatement()) {
			System.out.println("server=STOPPED (local status)");
			long events = count(statement, "events"), alerts = count(statement, "alerts"),
					incidents = count(statement, "incidents");
			System.out.println("activeConnections=0");
			System.out.println("queueSize=0");
			System.out.println("eventsReceived=" + events);
			System.out.println("eventsProcessed=" + events);
			System.out.println("eventsPersisted=" + events);
			System.out.println("alertsGenerated=" + alerts);
			System.out.println("incidentsGenerated=" + incidents);
		}
	}

	private static long count(java.sql.Statement statement, String table) throws java.sql.SQLException {
		try (var result = statement.executeQuery("select count(*) from " + table)) {
			result.next();
			return result.getLong(1);
		}
	}

	private static String configPath(String[] args, String fallback) {
		for (int i = 1; i < args.length; i++) {
			if (args[i].equals("--config") && i + 1 < args.length)
				return args[i + 1];
			if (!args[i].startsWith("--"))
				return args[i];
		}
		return fallback;
	}

	private static boolean desktopMode(String[] args) {
		return Arrays.asList(args).contains("--desktop");
	}
}
