package tech.humifortis.keycloak.mapper;

import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import tech.humifortis.keycloak.model.HumifortisEvent;

import java.time.Instant;

public class EventMapper {
    
    public HumifortisEvent fromKeycloakEvent(Event event) {
        HumifortisEvent humiEvent = new HumifortisEvent();
        
        // Entity ID: user:keycloak:{realm}:{userId or email}
        String entityId = String.format("user:keycloak:%s:%s", 
                event.getRealmId(), 
                event.getUserId() != null ? event.getUserId() : "anonymous");
        humiEvent.setEntityId(entityId);
        humiEvent.setEntityType("user");
        
        // Timestamp
        humiEvent.setTimestamp(Instant.ofEpochMilli(event.getTime()).toString());
        
        // Event type mapping
        humiEvent.setEventType(mapEventType(event.getType()));
        
        // Source
        humiEvent.setSource("keycloak");
        
        // Metadata
        humiEvent.addMetadata("realm", event.getRealmId());
        if (event.getClientId() != null) {
            humiEvent.addMetadata("client_id", event.getClientId());
        }
        if (event.getIpAddress() != null) {
            humiEvent.addMetadata("ip", event.getIpAddress());
        }
        if (event.getError() != null) {
            humiEvent.addMetadata("error", event.getError());
        }
        if (event.getSessionId() != null) {
            humiEvent.addMetadata("session_id", event.getSessionId());
        }
        humiEvent.addMetadata("keycloak_event_id", event.getTime() + "_" + event.getType().name());
        
        // Add details as metadata
        if (event.getDetails() != null && !event.getDetails().isEmpty()) {
            event.getDetails().forEach((key, value) -> {
                if ("username".equals(key) || "email".equals(key)) {
                    humiEvent.addMetadata(key, value);
                }
            });
        }
        
        return humiEvent;
    }

    public HumifortisEvent fromKeycloakAdminEvent(AdminEvent adminEvent) {
        HumifortisEvent humiEvent = new HumifortisEvent();
        
        // Entity ID for admin events
        String entityId = String.format("user:keycloak:%s:%s", 
                adminEvent.getRealmId(), 
                adminEvent.getAuthDetails() != null && adminEvent.getAuthDetails().getUserId() != null 
                        ? adminEvent.getAuthDetails().getUserId() 
                        : "admin");
        humiEvent.setEntityId(entityId);
        humiEvent.setEntityType("user");
        
        // Timestamp
        humiEvent.setTimestamp(Instant.ofEpochMilli(adminEvent.getTime()).toString());
        
        // Event type
        humiEvent.setEventType("admin_" + adminEvent.getOperationType().name().toLowerCase());
        
        // Source
        humiEvent.setSource("keycloak");
        
        // Metadata
        humiEvent.addMetadata("realm", adminEvent.getRealmId());
        humiEvent.addMetadata("resource_type", adminEvent.getResourceType().name());
        humiEvent.addMetadata("resource_path", adminEvent.getResourcePath());
        if (adminEvent.getError() != null) {
            humiEvent.addMetadata("error", adminEvent.getError());
        }
        
        return humiEvent;
    }

    private String mapEventType(EventType eventType) {
        return switch (eventType) {
            case LOGIN -> "auth_login_success";
            case LOGIN_ERROR -> "auth_login_failed";
            case LOGOUT -> "session_clean_logout";
            case REGISTER -> "auth_register";
            case UPDATE_PASSWORD -> "update_credential";
            case UPDATE_EMAIL -> "update_email";
            case VERIFY_EMAIL -> "auth_email_verify";
            case RESET_PASSWORD -> "reset_password";
            case RESET_PASSWORD_ERROR -> "reset_password_error";
            case CODE_TO_TOKEN -> "auth_token_exchange";
            case CODE_TO_TOKEN_ERROR -> "auth_token_exchange_failed";
            case REFRESH_TOKEN -> "auth_token_refresh";
            case REFRESH_TOKEN_ERROR -> "auth_token_refresh_failed";
            case INTROSPECT_TOKEN -> "auth_token_introspect";
            case INTROSPECT_TOKEN_ERROR -> "auth_token_introspect_failed";
            case REVOKE_GRANT -> "revoke_grant";
            case UPDATE_TOTP -> "mfa_token_enrolled";
            case REMOVE_TOTP -> "remove_credential";
            case SEND_VERIFY_EMAIL -> "auth_verify_email_sent";
            case SEND_RESET_PASSWORD -> "auth_reset_password_sent";
            case DELETE_ACCOUNT -> "delete_account";
            default -> "auth_" + eventType.name().toLowerCase();
        };
    }
}
