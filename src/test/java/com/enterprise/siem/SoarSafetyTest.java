package com.enterprise.siem;

import com.enterprise.siem.soar.ProcessExecutor;
import com.enterprise.siem.soar.ResponseAction;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class SoarSafetyTest {
    @Test
    void dryRunIsNonExecutingAndRealModeFailsClosed() throws Exception {
        var executor = new ProcessExecutor();
        assertEquals(0, executor.execute(ResponseAction.SIMULATE_ISOLATION, true));
        assertThrows(UnsupportedOperationException.class, () -> executor.execute(ResponseAction.SIMULATE_ISOLATION, false));
        assertEquals(3, executor.allowedActions().size());
    }
}
