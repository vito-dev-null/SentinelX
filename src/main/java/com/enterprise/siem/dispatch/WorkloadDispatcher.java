package com.enterprise.siem.dispatch;

import java.util.Objects;

public final class WorkloadDispatcher {
    public record Assignment(String taskId, WorkloadClass workloadClass, String workerId) {
    }

    private final WorkerRegistry registry;

    public WorkloadDispatcher(WorkerRegistry registry) {
        this.registry = Objects.requireNonNull(registry);
    }

    public Assignment dispatch(String taskId, WorkloadClass workloadClass) throws NoWorkerAvailableException {
        if (taskId == null || taskId.isBlank())
            throw new IllegalArgumentException("task id is required");
        Objects.requireNonNull(workloadClass, "workload class is required");
        if (!workloadClass.remoteOnly())
            throw new IllegalArgumentException("workload is not governed by the remote-only policy");
        registry.refresh();
        WorkerNode worker = registry.reserve();
        return new Assignment(taskId, workloadClass, worker.id());
    }

    public void release(String workerId) {
        registry.release(workerId);
    }
}
