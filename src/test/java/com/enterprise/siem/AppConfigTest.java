package com.enterprise.siem;

import com.enterprise.siem.config.AppConfig;
import org.junit.jupiter.api.Test;
import java.nio.file.Files;
import static org.junit.jupiter.api.Assertions.*;

class AppConfigTest {
    @Test
    void rejectsInvalidNumbersAndBooleans() throws Exception {
        var file = Files.createTempFile("sentinelx", ".properties");
        try {
            Files.writeString(file, "port=abc\nenabled=maybe\n");
            var config = new AppConfig(file.toString());
            assertThrows(IllegalArgumentException.class, () -> config.integer("port", 5050));
            assertThrows(IllegalArgumentException.class, () -> config.bool("enabled", true));
        } finally {
            Files.deleteIfExists(file);
        }
    }
}
