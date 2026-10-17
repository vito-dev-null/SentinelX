package com.enterprise.siem.dispatch;

import com.enterprise.siem.config.AppConfig;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class WorkerRegistry {
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(1)).build();
    private final Map<String, WorkerNode> workers = new LinkedHashMap<>();

    public WorkerRegistry(List<WorkerNode> nodes) {
        for (WorkerNode node : nodes) {
            if (workers.put(node.id(), node) != null)
                throw new IllegalArgumentException("duplicate worker: " + node.id());
        }
    }

    public static WorkerRegistry from(AppConfig config) {
        return new WorkerRegistry(List.of(
                new WorkerNode("nodo2", URI.create(config.get("worker.nodo2.url", "http://nodo2:8080"))),
                new WorkerNode("nodo3", URI.create(config.get("worker.nodo3.url", "http://nodo3:8080")))));
    }

    public synchronized List<WorkerNode> snapshot() {
        return new ArrayList<>(workers.values());
    }

    public synchronized void refresh() {
        for (WorkerNode worker : workers.values()) {
            if (worker.state() != WorkerState.BUSY)
                worker.state(probe(worker));
        }
    }

    public synchronized WorkerNode reserve() throws NoWorkerAvailableException {
        for (WorkerNode worker : workers.values().stream().sorted(Comparator.comparing(WorkerNode::id)).toList()) {
            if (worker.state() == WorkerState.AVAILABLE && claim(worker)) {
                worker.state(WorkerState.BUSY);
                return worker;
            }
        }
        throw new NoWorkerAvailableException("NO_WORKER_AVAILABLE");
    }

    public synchronized void release(String workerId) {
        WorkerNode worker = workers.get(workerId);
        if (worker != null) {
            releaseRemote(worker);
            worker.state(WorkerState.AVAILABLE);
        }
    }

    private WorkerState probe(WorkerNode worker) {
        try {
            HttpRequest request = HttpRequest.newBuilder(worker.endpoint().resolve("api/worker/status"))
                    .timeout(Duration.ofSeconds(2)).GET().build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 404)
                return probeHealth(worker);
            if (response.statusCode() < 200 || response.statusCode() >= 300)
                return WorkerState.OFFLINE;
            return response.body().toUpperCase().contains("BUSY") ? WorkerState.BUSY : WorkerState.AVAILABLE;
        } catch (IOException exception) {
            return WorkerState.OFFLINE;
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            return WorkerState.OFFLINE;
        }
    }

    private WorkerState probeHealth(WorkerNode worker) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(worker.endpoint().resolve("health"))
                .timeout(Duration.ofSeconds(2)).GET().build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        return response.statusCode() >= 200 && response.statusCode() < 300 ? WorkerState.AVAILABLE
                : WorkerState.OFFLINE;
    }

    private boolean claim(WorkerNode worker) {
        try {
            HttpRequest request = HttpRequest.newBuilder(worker.endpoint().resolve("api/worker/lease?action=acquire"))
                    .timeout(Duration.ofSeconds(2)).POST(HttpRequest.BodyPublishers.noBody()).build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            return response.statusCode() == 404 || (response.statusCode() >= 200 && response.statusCode() < 300);
        } catch (IOException exception) {
            return false;
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private void releaseRemote(WorkerNode worker) {
        try {
            HttpRequest request = HttpRequest.newBuilder(worker.endpoint().resolve("api/worker/lease?action=release"))
                    .timeout(Duration.ofSeconds(2)).POST(HttpRequest.BodyPublishers.noBody()).build();
            client.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException exception) {
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
        }
    }
}
