package com.enterprise.siem;

import com.enterprise.siem.config.RuleConfigLoader;
import com.enterprise.siem.model.Severity;
import org.junit.jupiter.api.Test;
import java.nio.file.Files;
import static org.junit.jupiter.api.Assertions.*;

class RuleConfigLoaderTest {
    @Test
    void loadsEnabledRulesAndConfiguredSeverity() throws Exception {
        var file = Files.createTempFile("rules", ".yaml");
        Files.writeString(file, "rules:\n  - id: SSH-BRUTE-FORCE\n    enabled: true\n    threshold: 2\n    windowSeconds: 30\n    severity: CRITICAL\n  - id: TRAFFIC-SPIKE\n    enabled: false\n");
        try {
            var rules = RuleConfigLoader.load(file.toString());
            assertEquals(1, rules.size());
            assertEquals(Severity.CRITICAL, rules.getFirst().getSeverity());
        } finally {
            Files.deleteIfExists(file);
        }
    }
}
