package tech.humifortis.keycloak.caep;

import java.util.Map;

public class CaepEventRegistry {
    static final String SESSION_REVOKED = "session-revoked";
    static final String ASSURANCE_LEVEL_CHANGE = "assurance-level-change";
    static final String RISK_LEVEL_CHANGE = "risk-level-change";
    // RISC (account lifecycle) events an analyst response can send: lock an account, force a new password
    static final String ACCOUNT_DISABLED = "account-disabled";
    static final String CREDENTIAL_COMPROMISE = "credential-compromise";
    // Humifortis event: a bounded time restriction on an entity's attempts (the standards have no temporary lockout)
    static final String THROTTLE = "throttle";

    private static final Map<String, String> URI_TO_EVENT = Map.ofEntries(
            Map.entry("https://schemas.openid.net/secevent/caep/event-type/session-revoked", SESSION_REVOKED),
            Map.entry("session-revoked", SESSION_REVOKED),
            Map.entry("session_revoked", SESSION_REVOKED),
            Map.entry("https://schemas.openid.net/secevent/caep/event-type/assurance-level-change", ASSURANCE_LEVEL_CHANGE),
            Map.entry("https://schemas.openid.net/secevent/caep/event-type/assurance-level-changed", ASSURANCE_LEVEL_CHANGE),
            Map.entry("assurance-level-change", ASSURANCE_LEVEL_CHANGE),
            Map.entry("assurance-level-changed", ASSURANCE_LEVEL_CHANGE),
            Map.entry("https://schemas.openid.net/secevent/caep/event-type/risk-level-change", RISK_LEVEL_CHANGE),
            Map.entry("risk-level-change", RISK_LEVEL_CHANGE),
            Map.entry("https://schemas.openid.net/secevent/risc/event-type/account-disabled", ACCOUNT_DISABLED),
            Map.entry("account-disabled", ACCOUNT_DISABLED),
            Map.entry("https://schemas.openid.net/secevent/risc/event-type/credential-compromise", CREDENTIAL_COMPROMISE),
            Map.entry("credential-compromise", CREDENTIAL_COMPROMISE),
            Map.entry("https://schemas.humifortis.dev/secevent/event-type/throttle", THROTTLE),
            Map.entry("throttle", THROTTLE)
    );

    public String resolve(String eventUri) {
        return URI_TO_EVENT.get(eventUri);
    }

    public boolean isEnabled(String event, CaepConfig config) {
        return switch (event) {
            case SESSION_REVOKED -> config.supportSessionRevoked();
            case ASSURANCE_LEVEL_CHANGE -> config.supportAssuranceLevelChange();
            case RISK_LEVEL_CHANGE -> config.supportAssuranceLevelChange();
            // always received; whether they CHANGE an account is gated by hf.caep.enforce.* (off by default)
            // the throttle is opted into on the core side (a tenant policy) and needs the realm's brute-force detection
            case ACCOUNT_DISABLED, CREDENTIAL_COMPROMISE, THROTTLE -> true;
            default -> false;
        };
    }
}
