package tech.humifortis.keycloak.model;

import java.util.HashMap;
import java.util.Map;

import com.google.gson.annotations.SerializedName;

public class HumifortisEvent {

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