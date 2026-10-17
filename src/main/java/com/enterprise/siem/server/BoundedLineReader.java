package com.enterprise.siem.server;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/** Reads one UTF-8 JSON Lines frame without buffering beyond the configured limit. */
final class BoundedLineReader implements AutoCloseable {
    static final class LineTooLargeException extends IOException {
        LineTooLargeException(int limit) { super("line exceeds " + limit + " bytes"); }
    }

    private final InputStream input;
    private final int maxBytes;

    BoundedLineReader(InputStream input, int maxBytes) {
        this.input = input;
        this.maxBytes = maxBytes;
    }

    String readLine() throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream(Math.min(maxBytes, 8192));
        int value;
        while ((value = input.read()) != -1) {
            if (value == '\n') return decode(bytes.toByteArray());
            if (bytes.size() == maxBytes) throw new LineTooLargeException(maxBytes);
            if (value != '\r') bytes.write(value);
        }
        return bytes.size() == 0 ? null : decode(bytes.toByteArray());
    }

    private static String decode(byte[] bytes) throws CharacterCodingException {
        CharBuffer decoded = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes));
        return decoded.toString();
    }

    @Override
    public void close() throws IOException { input.close(); }
}
