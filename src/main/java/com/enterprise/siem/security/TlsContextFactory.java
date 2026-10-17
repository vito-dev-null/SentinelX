package com.enterprise.siem.security;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.KeyStore;

public final class TlsContextFactory {
    private TlsContextFactory() { }

    public static SSLContext create(TlsConfiguration configuration) throws Exception {
        if (!configuration.enabled()) return null;
        if (configuration.keystore() == null || configuration.truststore() == null) {
            throw new IllegalArgumentException("TLS requires keystore and truststore paths");
        }
        KeyStore keyStore = load(configuration.keystore(), configuration.keystorePassword());
        KeyStore trustStore = load(configuration.truststore(), configuration.truststorePassword());
        KeyManagerFactory keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(keyStore, configuration.keystorePassword());
        TrustManagerFactory trusts = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trusts.init(trustStore);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keys.getKeyManagers(), trusts.getTrustManagers(), null);
        return context;
    }

    private static KeyStore load(java.nio.file.Path path, char[] password) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream input = Files.newInputStream(path)) {
            store.load(input, password);
        }
        return store;
    }
}
