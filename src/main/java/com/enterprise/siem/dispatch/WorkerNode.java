package com.enterprise.siem.dispatch;

import java.net.URI;

public final class WorkerNode {
    private final String id;
    private final URI endpoint;
    private WorkerState state = WorkerState.OFFLINE;

    public WorkerNode(String id, URI endpoint) {
        if (!SetOfWorkers.ALLOWED.contains(id))
            throw new IllegalArgumentException("controller cannot register local or unknown worker: " + id);
        this.id = id;
        this.endpoint = endpoint;
    }

    public String id() {
        return id;
    }

    public URI endpoint() {
        return endpoint;
    }

    public synchronized WorkerState state() {
        return state;
    }

    synchronized void state(WorkerState state) {
        this.state = state;
    }

    private static final class SetOfWorkers {
        private static final java.util.Set<String> ALLOWED = java.util.Set.of("nodo2", "nodo3");
    }
}
