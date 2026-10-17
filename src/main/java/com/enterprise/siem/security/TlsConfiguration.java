package com.enterprise.siem.security;

import java.nio.file.Path;

/** TLS settings reserved for a future SSL server/client transport. */
public record TlsConfiguration(boolean enabled, Path keystore, char[] keystorePassword,
                               Path truststore, char[] truststorePassword, boolean requireClientAuth) {
    public static TlsConfiguration disabled() {
        return new TlsConfiguration(false, null, new char[0], null, new char[0], false);
    }

    public static TlsConfiguration from(String enabled, String keystore, String keystorePassword,
                                        String truststore, String truststorePassword, boolean requireClientAuth) {
        boolean active = Boolean.parseBoolean(enabled);
        if (active && (keystore == null || keystore.isBlank() || truststore == null || truststore.isBlank()
            || keystorePassword == null || keystorePassword.isBlank() || truststorePassword == null || truststorePassword.isBlank())) {
            throw new IllegalArgumentException("TLS requires keystore, truststore and non-empty passwords");
        }
        return new TlsConfiguration(active, pathOrNull(keystore), chars(keystorePassword),
            pathOrNull(truststore), chars(truststorePassword), requireClientAuth);
    }

    public static TlsConfiguration from(String enabled, String keystore, String truststore) {
        return from(enabled, keystore, "", truststore, "", false);
    }

    private static char[] chars(String value) { return value == null ? new char[0] : value.toCharArray(); }

    private static Path pathOrNull(String value) {
        return value == null || value.isBlank() ? null : Path.of(value);
    }
}
