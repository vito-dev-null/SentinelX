package com.enterprise.siem.dispatch;

import com.enterprise.siem.config.AppConfig;

public final class ControllerApplication {
    private ControllerApplication() {
    }

    public static int run(String[] args, AppConfig config) {
        if (contains(args, "dispatch"))
            return dispatch(args, config);
        System.out.println("SENTINELX CONTROLLER: READY");
        System.out.println("POLICY: REMOTE-ONLY");
        System.out.println("WORKERS: nodo2,nodo3");
        return 0;
    }

    public static int dispatch(String[] args, AppConfig config) {
        String workload = valueAfter(args, "dispatch");
        String taskId = valueAfter(args, workload);
        if (workload == null || taskId == null) {
            System.err.println("usage: sentinelx-cli dispatch <WORKLOAD_CLASS> <TASK_ID>");
            return 2;
        }
        try {
            WorkloadClass workloadClass = WorkloadClass.parse(workload);
            var assignment = new WorkloadDispatcher(WorkerRegistry.from(config)).dispatch(taskId, workloadClass);
            System.out.printf("WORKER_ASSIGNED task=%s workload=%s worker=%s%n", assignment.taskId(),
                    assignment.workloadClass(), assignment.workerId());
            return 0;
        } catch (NoWorkerAvailableException exception) {
            System.err.println("NO_WORKER_AVAILABLE");
            return NoWorkerAvailableException.EXIT_CODE;
        } catch (IllegalArgumentException exception) {
            System.err.println(exception.getMessage());
            return 2;
        }
    }

    private static boolean contains(String[] args, String value) {
        for (String arg : args)
            if (value.equalsIgnoreCase(arg))
                return true;
        return false;
    }

    private static String valueAfter(String[] args, String value) {
        if (value == null)
            return null;
        for (int index = 0; index + 1 < args.length; index++)
            if (value.equalsIgnoreCase(args[index]))
                return args[index + 1];
        return null;
    }
}
