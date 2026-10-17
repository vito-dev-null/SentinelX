package com.enterprise.siem;

import com.enterprise.siem.security.TlsConfiguration;
import com.enterprise.siem.security.TlsContextFactory;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

class TlsConfigurationTest {
    @Test
    void enabledTlsRequiresBothStores() {
        var configuration = TlsConfiguration.from("true", "server.p12", "secret", "truststore.p12", "secret", true);
        assertThrows(Exception.class, () -> TlsContextFactory.create(configuration));
    }
}
