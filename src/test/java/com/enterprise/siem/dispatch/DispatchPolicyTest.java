package com.enterprise.siem.dispatch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.List;
import org.junit.jupiter.api.Test;

class DispatchPolicyTest {
    @Test
    void everyHeavyWorkloadIsRemoteOnly() {
        assertEquals(8, WorkloadClass.values().length);
        for (WorkloadClass workload : WorkloadClass.values())
            assertEquals(true, workload.remoteOnly());
    }

    @Test
    void localNodeCannotEnterWorkerRegistry() {
        assertThrows(IllegalArgumentException.class,
                () -> new WorkerNode("nodo1", URI.create("http://127.0.0.1:8080")));
    }

    @Test
    void unavailableWorkersReturnExitCode75() {
        var dispatcher = new WorkloadDispatcher(new WorkerRegistry(List.of()));
        var exception = assertThrows(NoWorkerAvailableException.class,
                () -> dispatcher.dispatch("task-1", WorkloadClass.BUILD));
        assertEquals(NoWorkerAvailableException.EXIT_CODE, exception.EXIT_CODE);
    }

    @Test
    void dispatcherAssignsOnlyAnAvailableRemoteWorker() throws Exception {
        HttpServer worker = HttpServer.create(new InetSocketAddress(0), 0);
        worker.createContext("/health", exchange -> {
            byte[] body = "{\"status\":\"UP\"}".getBytes();
            exchange.sendResponseHeaders(200, body.length);
            try (var output = exchange.getResponseBody()) {
                output.write(body);
            }
        });
        worker.start();
        try {
            URI endpoint = URI.create("http://127.0.0.1:" + worker.getAddress().getPort() + "/");
            var dispatcher = new WorkloadDispatcher(new WorkerRegistry(List.of(new WorkerNode("nodo2", endpoint))));
            assertEquals("nodo2", dispatcher.dispatch("task-2", WorkloadClass.CPU_HEAVY).workerId());
        } finally {
            worker.stop(0);
        }
    }

    @Test
    void reservedWorkerIsNotReusedUntilReleased() throws Exception {
        HttpServer worker = HttpServer.create(new InetSocketAddress(0), 0);
        worker.createContext("/health", exchange -> exchange.sendResponseHeaders(200, -1));
        worker.start();
        try {
            URI endpoint = URI.create("http://127.0.0.1:" + worker.getAddress().getPort() + "/");
            var dispatcher = new WorkloadDispatcher(new WorkerRegistry(List.of(new WorkerNode("nodo2", endpoint))));
            dispatcher.dispatch("task-3", WorkloadClass.BATCH);
            assertEquals(NoWorkerAvailableException.EXIT_CODE,
                    org.junit.jupiter.api.Assertions.assertThrows(NoWorkerAvailableException.class,
                            () -> dispatcher.dispatch("task-4", WorkloadClass.BUILD)).EXIT_CODE);
        } finally {
            worker.stop(0);
        }
    }
}