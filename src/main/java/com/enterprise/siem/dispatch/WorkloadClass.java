package com.enterprise.siem.dispatch;

import java.util.Locale;

public enum WorkloadClass {
    BUILD,
    COMPILE,
    TEST_CPU,
    CPU_HEAVY,
    BACKGROUND,
    SERVICES,
    WORKERS,
    BATCH;

    public static WorkloadClass parse(String value) {
        if (value == null || value.isBlank())
            throw new IllegalArgumentException("workload class is required");
        try {
            return WorkloadClass.valueOf(value.trim().toUpperCase(Locale.ROOT).replace('-', '_'));
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("unsupported workload class: " + value, exception);
        }
    }

    public boolean remoteOnly() {
        return true;
    }
}
