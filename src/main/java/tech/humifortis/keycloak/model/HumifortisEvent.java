package tech.humifortis.keycloak.model;

import java.util.HashMap;
import java.util.Map;

import com.google.gson.annotations.SerializedName;

public class HumifortisEvent {

    /**
     * Source event ID — the UUID assigned by the origin system (Keycloak event.getId()).
     * Used by humifortis-core for idempotent deduplication:
     *   same event_id = skip re-processing even on retries or network duplicates.
     * Null for synthetic events that have no upstream ID.
     */
    @SerializedName("event_id")
    private String eventId;

    /**
     * Flow ID — the authentication session identifier that groups all events
     * belonging to a single authentication attempt (login → MFA → decision).
     *
     * Extraction priority (Keycloak):
     *   1. event.getDetails().get("authSessionId")   — standard auth flows
     *   2. event.getDetails().get("code_id")          — OIDC authorization code flows
     *   3. event.getSessionId()                        — post-auth fallback
     *
     * MANDATORY for all auth events — must never be null/empty.
     * humifortis-core rejects auth events without a flow_id.
     */
    @SerializedName("flow_id")
    private String flowId;

    @SerializedName("entity_id")
    private String entityId;

    @SerializedName("entity_type")
    private String entityType;

    private String timestamp;

    @SerializedName("event_type")
    private String eventType;

    private String source;

    /**
     * resource carries admin event targeting context:
     * which object was touched, what operation, what path.
     * Null for non-admin events.
     */
    private Map<String, String> resource;

    private Map<String, Object> metadata;

    public HumifortisEvent() {
        this.metadata = new HashMap<>();
    }

    public String getEventId() { return eventId; }
    public void setEventId(String eventId) { this.eventId = eventId; }

    public String getFlowId() { return flowId; }
    public void setFlowId(String flowId) { this.flowId = flowId; }

    public String getEntityId() { return entityId; }
    public void setEntityId(String entityId) { this.entityId = entityId; }

    public String getEntityType() { return entityType; }
    public void setEntityType(String entityType) { this.entityType = entityType; }

    public String getTimestamp() { return timestamp; }
    public void setTimestamp(String timestamp) { this.timestamp = timestamp; }

    public String getEventType() { return eventType; }
    public void setEventType(String eventType) { this.eventType = eventType; }

    public String getSource() { return source; }
    public void setSource(String source) { this.source = source; }

    public Map<String, String> getResource() { return resource; }
    public void setResource(Map<String, String> resource) { this.resource = resource; }

    public Map<String, Object> getMetadata() { return metadata; }
    public void setMetadata(Map<String, Object> metadata) { this.metadata = metadata; }

    public void addMetadata(String key, Object value) {
        if (key != null && value != null) {
            this.metadata.put(key, value);
        }
    }

    public void addResource(String key, String value) {
        if (key != null && value != null) {
            if (this.resource == null) this.resource = new HashMap<>();
            this.resource.put(key, value);
        }
    }
}