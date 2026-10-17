package com.enterprise.siem.dispatch;

public final class NoWorkerAvailableException extends Exception {
    public static final int EXIT_CODE = 75;

    public NoWorkerAvailableException(String message) {
        super(message);
    }
}
