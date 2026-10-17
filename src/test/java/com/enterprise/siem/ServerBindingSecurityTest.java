package com.enterprise.siem;

import com.enterprise.siem.security.TlsConfiguration;
import com.enterprise.siem.server.EnterpriseSIEMServer;
import com.enterprise.siem.util.SIEMMetrics;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ServerBindingSecurityTest {
    @Test
    void permitsLoopbackWithoutTls() throws Exception {
        assertDoesNotThrow(() -> {
            try (var ignored = new EnterpriseSIEMServer(0, null, null, new SIEMMetrics(),
                    1, 1, 1024, TlsConfiguration.disabled(), 1, InetAddress.getByName("127.0.0.1"))) {
            }
        });
    }

    @Test
    void rejectsNonLoopbackWithoutMutualTls() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> new EnterpriseSIEMServer(0, null, null,
                new SIEMMetrics(), 1, 1, 1024, TlsConfiguration.disabled(), 1,
                InetAddress.getByName("0.0.0.0")));
    }

    @Test
    void permitsNonLoopbackOnlyWithMutualTls() throws Exception {
        var tls = TlsConfiguration.from("true", "server.p12", "password", "truststore.p12", "password", true);
        assertDoesNotThrow(() -> {
            try (var ignored = new EnterpriseSIEMServer(0, null, null, new SIEMMetrics(),
                    1, 1, 1024, tls, 1, InetAddress.getByName("0.0.0.0"))) {
            }
        });
    }
}
