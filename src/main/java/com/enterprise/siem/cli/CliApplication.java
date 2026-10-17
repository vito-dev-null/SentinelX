package com.enterprise.siem.cli;

import com.enterprise.siem.util.JsonUtil;
import com.enterprise.siem.config.AppConfig;
import com.enterprise.siem.dispatch.ControllerApplication;
import com.fasterxml.jackson.databind.JsonNode;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicBoolean;

/** Read-only terminal client for the running SentinelX service. */
public final class CliApplication {
    private static final String RESET = "\033[0m";
    private static final String CYAN = "\033[36m";
    private static final String GREEN = "\033[32m";
    private static final String YELLOW = "\033[33m";
    private static final String RED = "\033[31m";
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
    private final String baseUrl;
    private final int columns;

    private CliApplication(String baseUrl) {
        this.baseUrl = baseUrl.replaceAll("/$", "");
        this.columns = terminalColumns();
    }

    public static void run(String[] args) {
        String baseUrl = System.getenv().getOrDefault("SENTINELX_SOC_URL", "http://127.0.0.1:8080");
        CliApplication cli = new CliApplication(baseUrl);
        String command = args.length > 1 && !args[1].startsWith("--") ? args[1].toLowerCase(Locale.ROOT) : "cli";
        try {
            switch (command) {
                case "cli" -> cli.monitor();
                case "status" -> cli.printEndpoint("/api/status", "STATUS");
                case "health" -> cli.printEndpoint("/health", "HEALTH");
                case "network" -> cli.live("/api/network", "NETWORK SENSOR", has(args, "--live"));
                case "capture-test" -> cli.printEndpoint("/api/capture-test", "CAPTURE TEST");
                case "flows" -> cli.live("/api/flows", "LIVE FLOWS", has(args, "--live"));
                case "alerts" -> cli.live("/api/alerts?size=100", "ALERTS", has(args, "--live"));
                case "incidents" -> cli.printEndpoint("/api/incidents?size=100", "INCIDENTS");
                case "events" -> cli.live("/api/events?size=100", "EVENTS", has(args, "--follow"));
                case "nodes" -> cli.printEndpoint("/api/nodes", "ENDPOINTS");
                case "interfaces" -> cli.interfaces();
                case "config" -> cli.config();
                case "logs" -> cli.logs(has(args, "--follow"));
                case "dispatch" -> System.exit(ControllerApplication.dispatch(args,
                        new AppConfig(configPath(args, "config/server.properties"))));
                default -> cli.usage();
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
        } catch (Exception exception) {
            String detail = exception.getMessage() == null ? exception.getClass().getSimpleName()
                    : exception.getMessage();
            cli.error("CLI error: " + detail);
        }
    }

    private void monitor() throws Exception {
        AtomicBoolean running = new AtomicBoolean(true);
        Thread input = new Thread(() -> {
            try {
                while (running.get()) {
                    int value = System.in.read();
                    if (value < 0 || value == 'q' || value == 'Q') {
                        running.set(false);
                        break;
                    }
                    if (value == 'r' || value == 'R')
                        System.out.print("\033[2J\033[H");
                }
            } catch (IOException ignored) {
                running.set(false);
            }
        }, "sentinelx-cli-input");
        input.setDaemon(true);
        input.start();
        while (running.get()) {
            System.out.print("\033[2J\033[H");
            header();
            printJson(fetch("/api/network"), "NETWORK SENSOR");
            printJson(fetch("/api/metrics"), "SIEM METRICS");
            printJson(fetch("/api/flows"), "LIVE FLOWS");
            System.out.println("\n" + CYAN + "Controls: q quit  r refresh" + RESET);
            Thread.sleep(1000);
        }
    }

    private void live(String path, String title, boolean follow) throws Exception {
        String previous = null;
        do {
            String body = fetchRaw(path);
            if (!body.equals(previous) || !follow) {
                System.out.print("\033[2J\033[H");
                header();
                printJson(JsonUtil.mapper().readTree(body), title);
                if (follow)
                    System.out.println("\n" + CYAN + "Press q then Enter to quit" + RESET);
                previous = body;
            }
            if (!follow)
                return;
            if (System.in.available() > 0) {
                int key = System.in.read();
                if (key == 'q' || key == 'Q')
                    return;
            }
            Thread.sleep(1000);
        } while (true);
    }

    private void printEndpoint(String path, String title) throws Exception {
        header();
        printJson(fetch(path), title);
    }

    private void printJson(JsonNode node, String title) {
        System.out.println(CYAN + "\n=== " + title + " ===" + RESET);
        if (node == null || node.isMissingNode() || node.isNull() || (node.isArray() && node.isEmpty())) {
            System.out.println(YELLOW + (title.contains("FLOW") ? "NO ACTIVE FLOWS" : "NO DATA") + RESET);
            return;
        }
        for (String line : node.toPrettyString().split("\\R"))
            System.out.println(limit(line));
    }

    private void header() {
        System.out.println(GREEN + "SENTINELX 3 :: NETWORK SECURITY OPERATIONS CENTER" + RESET);
        String timestamp = "N/A";
        String source = "UNKNOWN";
        try {
            JsonNode time = fetch("/api/time");
            timestamp = time.path("timestampUtc").asText("N/A");
            source = time.path("source").asText("UNKNOWN");
        } catch (Exception ignored) {
        }
        System.out.println("TIME: " + timestamp + "  SOURCE: " + source + "  |  q=quit r=refresh");
    }

    private void interfaces() throws IOException {
        header();
        Enumeration<java.net.NetworkInterface> devices = java.net.NetworkInterface.getNetworkInterfaces();
        List<java.net.NetworkInterface> values = new ArrayList<>();
        while (devices != null && devices.hasMoreElements())
            values.add(devices.nextElement());
        values.sort(Comparator.comparing(java.net.NetworkInterface::getName));
        for (var device : values) {
            List<String> addresses = new ArrayList<>();
            device.getInterfaceAddresses().forEach(address -> addresses.add(address.getAddress().getHostAddress()));
            System.out.printf("%-16s %-8s %-8s %s%n", device.getName(), device.isUp() ? "UP" : "DOWN",
                    device.isLoopback() ? "LOOPBACK" : "NETWORK", addresses);
        }
    }

    private void config() throws IOException {
        header();
        Properties properties = new Properties();
        try (var input = Files.newInputStream(Path.of("config/server.properties"))) {
            properties.load(input);
        }
        properties.stringPropertyNames().stream().sorted().forEach(key -> {
            String value = key.toLowerCase(Locale.ROOT).contains("password") ? "REDACTED" : properties.getProperty(key);
            System.out.println(key + "=" + value);
        });
    }

    private void logs(boolean follow) throws IOException, InterruptedException {
        Path file = Path.of("logs/desktop-launcher.log");
        long position = Files.exists(file) ? Files.size(file) : 0;
        do {
            if (Files.exists(file)) {
                byte[] data = Files.readAllBytes(file);
                if (position < data.length) {
                    System.out.print(new String(data, (int) position, data.length - (int) position));
                    position = data.length;
                }
            }
            if (!follow)
                return;
            Thread.sleep(1000);
        } while (true);
    }

    private JsonNode fetch(String path) throws Exception {
        return JsonUtil.mapper().readTree(fetchRaw(path));
    }

    private String fetchRaw(String path) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + path)).timeout(Duration.ofSeconds(3)).GET()
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300)
            throw new IOException("API " + response.statusCode());
        return response.body();
    }

    private void error(String message) {
        System.err.println(RED + message + RESET);
    }

    private void usage() {
        System.out.println(
                "sentinelx [cli|status|network|capture-test|flows|alerts|incidents|events|nodes|interfaces|config|health|logs|dispatch] [--live|--follow]");
    }

    private static String configPath(String[] args, String fallback) {
        for (int index = 0; index + 1 < args.length; index++)
            if ("--config".equals(args[index]))
                return args[index + 1];
        return fallback;
    }

    private static boolean has(String[] args, String value) {
        for (String arg : args)
            if (value.equals(arg))
                return true;
        return false;
    }

    private static int terminalColumns() {
        try {
            return Math.max(80, Integer.parseInt(System.getenv().getOrDefault("COLUMNS", "120")));
        } catch (NumberFormatException ignored) {
            return 120;
        }
    }

    private String limit(String value) {
        return value.length() <= columns ? value : value.substring(0, Math.max(0, columns - 1));
    }
}
