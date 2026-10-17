package com.enterprise.siem.model;
import java.time.Instant;
import java.util.UUID;
public record Incident(UUID incidentId, Instant createdAt, Instant updatedAt, Instant resolvedAt, Severity severity, String title, String description, String status, String responseAction) {
    public Incident { incidentId = incidentId == null ? UUID.randomUUID() : incidentId; createdAt = createdAt == null ? Instant.now() : createdAt; updatedAt = updatedAt == null ? createdAt : updatedAt; status = status == null ? IncidentStatus.OPEN.name() : status; }
    public Incident(UUID incidentId, Instant createdAt, Severity severity, String title, String description, String status, String responseAction) { this(incidentId, createdAt, createdAt, null, severity, title, description, status, responseAction); }
    public Incident withStatus(IncidentStatus next) { Instant now=Instant.now(); return new Incident(incidentId, createdAt, now, next==IncidentStatus.RESOLVED?now:resolvedAt, severity, title, description, next.name(), responseAction); }
}
