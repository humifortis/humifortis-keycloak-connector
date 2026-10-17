package tech.humifortis.keycloak.auth;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.Map;

/**
 * The three tests of the evaluation context that are not the platform decision itself (docs/risk-as-data.spec.md,
 * D4): <em>risk level at least X</em>, <em>rule Y fired</em>, <em>attribute Z equals V</em>. Each is a Keycloak
 * condition with its own configuration; flows combine them with the flow structure of Keycloak.
 */
public final class ContextCondition implements ConditionalAuthenticator {

    private static final Logger logger = Logger.getLogger(ContextCondition.class);

    enum Kind { RISK_LEVEL, RULE_FIRED, ATTRIBUTE }

    static final String CONFIG_LEVEL = "level";
    static final String CONFIG_RULE = "rule";
    static final String CONFIG_ATTRIBUTE = "attribute";
    static final String CONFIG_VALUE = "value";

    private final Kind kind;

    ContextCondition(Kind kind) {
        this.kind = kind;
    }

    /** The notes of an authentication session as the pure conditions read them. */
    static ContextNotes.Notes notesOf(AuthenticationSessionModel s) {
        return new ContextNotes.Notes() {
            @Override public String get(String key) { return s.getAuthNote(key); }
            @Override public void set(String key, String value) { s.setAuthNote(key, value); }
            @Override public void remove(String key) { s.removeAuthNote(key); }
        };
    }

    @Override
    public boolean matchCondition(AuthenticationFlowContext context) {
        Map<String, String> config = configOf(context);
        ContextNotes.Notes notes = notesOf(context.getAuthenticationSession());
        boolean match = switch (kind) {
            case RISK_LEVEL -> ContextConditions.riskLevelAtLeast(notes, config.get(CONFIG_LEVEL));
            case RULE_FIRED -> ContextConditions.ruleFired(notes, config.get(CONFIG_RULE));
            case ATTRIBUTE -> attribute(notes, config);
        };
        logger.debugf("[Humifortis condition %s] match=%s", kind, match);
        return match;
    }

    private static boolean attribute(ContextNotes.Notes notes, Map<String, String> config) {
        String name = config.get(CONFIG_ATTRIBUTE);
        if (name != null && !DecisionSource.attributeAllowlist().contains(name.trim())) {
            // not an error of the login: the attribute is outside the allowlist, so it is never written (D13)
            logger.warnf("[Humifortis condition ATTRIBUTE] '%s' is not in HUMIFORTIS_CONTEXT_ATTRIBUTES: it never matches", name);
            return false;
        }
        return ContextConditions.attributeEquals(notes, name, config.get(CONFIG_VALUE));
    }

    static Map<String, String> configOf(AuthenticationFlowContext context) {
        AuthenticatorConfigModel model = context.getAuthenticatorConfig();
        return model != null && model.getConfig() != null ? model.getConfig() : Map.of();
    }

    @Override public void authenticate(AuthenticationFlowContext context) { context.success(); }
    @Override public void action(AuthenticationFlowContext context) { context.success(); }
    @Override public boolean requiresUser() { return true; }
    @Override public boolean configuredFor(KeycloakSession s, RealmModel r, UserModel u) { return true; }
    @Override public void setRequiredActions(KeycloakSession s, RealmModel r, UserModel u) {}
    @Override public void close() {}
}
