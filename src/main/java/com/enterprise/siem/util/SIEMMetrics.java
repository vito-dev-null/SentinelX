package com.enterprise.siem.util;
import java.util.concurrent.atomic.LongAdder;
import java.util.concurrent.atomic.AtomicInteger;
public final class SIEMMetrics {
    public final LongAdder eventsReceived = new LongAdder(), eventsAccepted = new LongAdder(), eventsRejected = new LongAdder(), malformedEvents = new LongAdder(), oversizedEvents = new LongAdder(), eventsPersisted = new LongAdder(), eventsProcessed = new LongAdder(), alertsGenerated = new LongAdder(), incidentsGenerated = new LongAdder(), databaseErrors = new LongAdder(), processingErrors = new LongAdder(), correlationErrors = new LongAdder(), evictedKeys = new LongAdder(), droppedEvents = new LongAdder(), eventsDropped = new LongAdder(), auditFailures = new LongAdder(), soarActions = new LongAdder(), soarFailures = new LongAdder(), ruleEvaluations = new LongAdder(), ruleErrors = new LongAdder();
    public final AtomicInteger activeConnections = new AtomicInteger(), activeCorrelationKeys = new AtomicInteger(), queueSize = new AtomicInteger(), queueHighWaterMark = new AtomicInteger();
}
