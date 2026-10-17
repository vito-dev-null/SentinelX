package com.enterprise.siem.agent;

import com.enterprise.siem.security.InputValidator;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.function.Consumer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class LogFileWatcher implements Runnable {
	private static final Logger log = LoggerFactory.getLogger(LogFileWatcher.class);
	private final Path file;
	private final Consumer<String> sink;
	private volatile boolean running = true;
	public LogFileWatcher(Path file, Consumer<String> sink) { this.file = file; this.sink = sink; }
	public void stop() { running = false; }
	@Override public void run() {
		long position = 0; Object fileKey = null; var pending = new ByteArrayOutputStream();
		while (running && !Thread.currentThread().isInterrupted()) try {
			if (!Files.exists(file)) { Thread.sleep(1000); continue; }
			Object currentKey = Files.getAttribute(file, "basic:fileKey"); long size = Files.size(file);
			if ((fileKey != null && !fileKey.equals(currentKey)) || size < position) { position = 0; pending.reset(); }
			fileKey = currentKey;
			try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ)) {
				channel.position(position); ByteBuffer buffer = ByteBuffer.allocate(8192); int read;
				while (running && (read = channel.read(buffer)) > 0) { buffer.flip(); for (int i = 0; i < read; i++) { byte value = buffer.get(); if (value == '\n') { emit(pending.toByteArray()); pending.reset(); } else if (pending.size() < InputValidator.MAX_EVENT_BYTES) pending.write(value); else pending.reset(); } buffer.clear(); }
				position = channel.position();
			}
			Thread.sleep(300);
		} catch (InterruptedException exception) { Thread.currentThread().interrupt(); }
		  catch (IOException exception) { try { Thread.sleep(1000); } catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); } }
	}
	private void emit(byte[] bytes) { if (bytes.length >= InputValidator.MAX_EVENT_BYTES) { log.warn("Dropped oversized log line from {}", file); return; } try { sink.accept(StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()); } catch (java.nio.charset.CharacterCodingException exception) { log.warn("Dropped invalid UTF-8 log line from {}", file); } }
}
