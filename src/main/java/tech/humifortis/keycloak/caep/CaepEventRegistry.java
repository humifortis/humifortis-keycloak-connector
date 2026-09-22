package tech.humifortis.keycloak.caep;

import java.util.Map;

public class CaepEventRegistry {
    static final String SESSION_REVOKED = "session-revoked";
    static final String ASSURANCE_LEVEL_CHANGE = "assurance-level-change";
    static final String RISK_LEVEL_CHANGE = "risk-level-change";

    private static final Map<String, String> URI_TO_EVENT = Map.ofEntries(
            Map.entry("https://schemas.openid.net/secevent/caep/event-type/session-revoked", SESSION_REVOKED),
            Map.entry("session-revoked", SESSION_REVOKED),
            Map.entry("session_revoked", SESSION_REVOKED),
            Map.entry("https://schemas.openid.net/secevent/caep/event-type/assurance-level-change", ASSURANCE_LEVEL_CHANGE),
            Map.entry("https://schemas.openid.net/secevent/caep/event-type/assurance-level-changed", ASSURANCE_LEVEL_CHANGE),
            Map.entry("assurance-level-change", ASSURANCE_LEVEL_CHANGE),
            Map.entry("assurance-level-changed", ASSURANCE_LEVEL_CHANGE),
            Map.entry("https://schemas.openid.net/secevent/caep/event-type/risk-level-change", RISK_LEVEL_CHANGE),
            Map.entry("risk-level-change", RISK_LEVEL_CHANGE)
    );

    public String resolve(String eventUri) {
        return URI_TO_EVENT.get(eventUri);
    }

    public boolean isEnabled(String event, CaepConfig config) {
        return switch (event) {
            case SESSION_REVOKED -> config.supportSessionRevoked();
            case ASSURANCE_LEVEL_CHANGE -> config.supportAssuranceLevelChange();
            case RISK_LEVEL_CHANGE -> config.supportAssuranceLevelChange();
            default -> false;
        };
    }
}
