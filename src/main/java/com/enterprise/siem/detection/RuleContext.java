package com.enterprise.siem.detection;
import com.enterprise.siem.model.SecurityEvent;
import java.util.ArrayList;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.LongAdder;
public final class RuleContext {
    private static final int DEFAULT_MAX_KEYS = 10_000;
    private static final int DEFAULT_MAX_EVENTS_PER_KEY = 4096;
    private static final Duration DEFAULT_KEY_TTL = Duration.ofMinutes(15);
    private record Window(ArrayDeque<SecurityEvent> events, Instant lastAccess) { }
    private final Map<String, Window> windows = new HashMap<>();
    private final int maxKeys;
    private final int maxEventsPerKey;
    private final Duration keyTtl;
    private final LongAdder evictedKeys = new LongAdder();
    private final LongAdder droppedEvents = new LongAdder();
    private long operations;

    public RuleContext() { this(DEFAULT_MAX_KEYS, DEFAULT_MAX_EVENTS_PER_KEY, DEFAULT_KEY_TTL); }
    public RuleContext(int maxKeys, int maxEventsPerKey, Duration keyTtl) {
        if (maxKeys <= 0 || maxEventsPerKey <= 0 || keyTtl.isNegative() || keyTtl.isZero()) throw new IllegalArgumentException("invalid correlation limits");
        this.maxKeys = maxKeys; this.maxEventsPerKey = maxEventsPerKey; this.keyTtl = keyTtl;
    }
    public synchronized ArrayList<SecurityEvent> recent(String key, SecurityEvent current, Duration window) {
        if (key == null || current == null || window.isNegative() || window.isZero()) { droppedEvents.increment(); return new ArrayList<>(); }
        Instant now = Instant.now();
        cleanup(now);
        Window state = windows.get(key);
        if (state == null) {
            if (windows.size() >= maxKeys) evictLeastRecentlyUsed();
            state = new Window(new ArrayDeque<>(), now);
        }
        state.events().addLast(current);
        while (!state.events().isEmpty() && state.events().peekFirst().timestamp().isBefore(current.timestamp().minus(window))) state.events().pollFirst();
        while (state.events().size() > maxEventsPerKey) { state.events().pollFirst(); droppedEvents.increment(); }
        windows.put(key, new Window(state.events(), now));
        return new ArrayList<>(state.events());
    }
    public ArrayList<SecurityEvent> recentGlobal(String key, SecurityEvent current, Duration window) {
        return recent("global:" + key, current, window);
    }
    public ArrayList<SecurityEvent> recentForAgent(String key, String agentId, SecurityEvent current, Duration window) {
        return recent("agent:" + agentId + ":" + key, current, window);
    }
    public synchronized void cleanup() { cleanup(Instant.now()); }
    public synchronized void clear() { windows.clear(); }
    public synchronized int activeKeys() { cleanup(Instant.now()); return windows.size(); }
    public long evictedKeys() { return evictedKeys.sum(); }
    public long droppedEvents() { return droppedEvents.sum(); }
    private void cleanup(Instant now) {
        if (++operations % 128 != 0 && windows.size() < maxKeys) return;
        windows.entrySet().removeIf(entry -> Duration.between(entry.getValue().lastAccess(), now).compareTo(keyTtl) > 0);
    }
    private void evictLeastRecentlyUsed() {
        var least = windows.entrySet().stream().min(Map.Entry.comparingByValue((left, right) -> left.lastAccess().compareTo(right.lastAccess())));
        if (least.isPresent()) { windows.remove(least.get().getKey()); evictedKeys.increment(); }
    }
}
