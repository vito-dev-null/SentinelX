package com.enterprise.siem.server;

import org.junit.jupiter.api.Test;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import static org.junit.jupiter.api.Assertions.*;

class BoundedLineReaderTest {
    @Test
    void acceptsExactLimitAndUnterminatedLine() throws Exception {
        try (var reader = new BoundedLineReader(new ByteArrayInputStream("abc\n".getBytes(StandardCharsets.UTF_8)), 3)) {
            assertEquals("abc", reader.readLine());
            assertNull(reader.readLine());
        }
        try (var reader = new BoundedLineReader(new ByteArrayInputStream("abc".getBytes(StandardCharsets.UTF_8)), 3)) {
            assertEquals("abc", reader.readLine());
        }
    }

    @Test
    void rejectsOversizedAndInvalidUtf8Lines() {
        assertThrows(BoundedLineReader.LineTooLargeException.class, () -> {
            try (var reader = new BoundedLineReader(new ByteArrayInputStream("abcd".getBytes(StandardCharsets.UTF_8)), 3)) { reader.readLine(); }
        });
        assertThrows(java.nio.charset.CharacterCodingException.class, () -> {
            try (var reader = new BoundedLineReader(new ByteArrayInputStream(new byte[] {(byte) 0xc3, (byte) 0x28, '\n'}), 10)) { reader.readLine(); }
        });
    }
}
