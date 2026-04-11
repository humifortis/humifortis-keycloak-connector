
package tech.humifortis.keycloak.model;

import java.util.Map;

import com.google.gson.annotations.SerializedName;

public class RiskDecision {
        public String getRiskLevel() {
            if (metadata != null && metadata.containsKey("risk_level")) {
                Object riskLevel = metadata.get("risk_level");
                if (riskLevel != null) {
                    return riskLevel.toString();
                }
            }
            return null;
        }
    public enum Action {
        ALLOW, CHALLENGE_MFA, BLOCK
    }

    @SerializedName("entity_id")
    private String entityId;
    
    private Action action;
    private String reason;
    
    @SerializedName("message_to_user")
    private String messageToUser;
    
    private Map<String, Object> metadata;
    
    @SerializedName("ttl_seconds")
    private Integer ttlSeconds;
    
    private String timestamp;

    public String getEntityId() {
        return entityId;
    }

    public void setEntityId(String entityId) {
        this.entityId = entityId;
    }

    public Action getAction() {
        return action;
    }

    public void setAction(Action action) {
        this.action = action;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public String getMessageToUser() {
        return messageToUser;
    }

    public void setMessageToUser(String messageToUser) {
        this.messageToUser = messageToUser;
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    public void setMetadata(Map<String, Object> metadata) {
        this.metadata = metadata;
    }

    public Integer getTtlSeconds() {
        return ttlSeconds;
    }

    public void setTtlSeconds(Integer ttlSeconds) {
        this.ttlSeconds = ttlSeconds;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }

    public Integer getRiskScore() {
        if (metadata != null && metadata.containsKey("risk_score")) {
            Object riskScore = metadata.get("risk_score");
            if (riskScore instanceof Number) {
                return ((Number) riskScore).intValue();
            }
        }
        return null;
    }

    public static RiskDecision allow() {
        RiskDecision decision = new RiskDecision();
        decision.setAction(Action.ALLOW);
        decision.setReason("New entity, default allow");
        return decision;
    }
}
