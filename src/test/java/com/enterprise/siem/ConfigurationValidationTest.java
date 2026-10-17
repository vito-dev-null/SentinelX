package com.enterprise.siem;

import com.enterprise.siem.config.RuleConfigLoader;
import org.junit.jupiter.api.Test;
import java.nio.file.Files;
import static org.junit.jupiter.api.Assertions.*;

class ConfigurationValidationTest {
    @Test
    void rejectsUnknownRuleAndInvalidThreshold() throws Exception {
        var unknown = Files.createTempFile("rules", ".yaml");
        var invalid = Files.createTempFile("rules", ".yaml");
        try {
            Files.writeString(unknown, "rules:\n  - id: UNKNOWN\n    enabled: true\n");
            Files.writeString(invalid, "rules:\n  - id: SSH-BRUTE-FORCE\n    threshold: 0\n    windowSeconds: 60\n    severity: HIGH\n");
            assertThrows(java.io.IOException.class, () -> RuleConfigLoader.load(unknown.toString()));
            assertThrows(java.io.IOException.class, () -> RuleConfigLoader.load(invalid.toString()));
        } finally {
            Files.deleteIfExists(unknown);
            Files.deleteIfExists(invalid);
        }
    }
}
