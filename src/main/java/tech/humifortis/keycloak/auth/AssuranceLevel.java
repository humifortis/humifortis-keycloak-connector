package tech.humifortis.keycloak.auth;

import java.util.Map;

import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.authentication.authenticators.util.AcrStore;
import org.keycloak.models.ClientModel;
import org.keycloak.protocol.oidc.utils.AcrUtils;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * The assurance ladder as the {@code acr} of a token (docs/sso-and-external-idp-e2e.spec.md, P13, RFC 9470).
 *
 * <p>Two directions. <em>Asked:</em> a request that carries {@code acr_values} (an API sent the person back because her token
 * is not strong enough) is evaluated with the level it asks for, and Humifortis decides the factor that reaches it.
 * <em>Reached:</em> when the step-up Humifortis decided completes, the level of the factor is recorded as Keycloak's level of
 * authentication, so the token's {@code acr} says what the person really did.</p>
 *
 * <p>The levels are the ladder's (1 a code, 2 an app, 3 a phishing-resistant factor): the realm maps its acr names to them with
 * Keycloak's own setting, {@code acr.loa.map}, e.g. {@code {"urn:humifortis:acr:app": 2}}. A bare number is understood too.
 * A password alone is no level: it carries no {@code acr} of this ladder.</p>
 */
public final class AssuranceLevel {

    private static final Logger LOG = Logger.getLogger(AssuranceLevel.class);

    /** The highest level of the ladder. */
    static final int MAX_LEVEL = 3;
    /** Auth note: the level the decision reached with the factor it asked (core's achieved_assurance). */
    public static final String NOTE_ACHIEVED_LEVEL = "HUMIFORTIS_ACHIEVED_ASSURANCE";

    private AssuranceLevel() {}

    /**
     * The level an {@code acr_values} string asks for: the first value the realm maps or that is a plain level, 0 when none is.
     * RFC 9470 lists the values in order of preference. A level above the ladder is the top of the ladder, never ignored: a
     * request for more than anything is not a request for nothing.
     */
    public static int requested(String acrValues, Map<String, Integer> loaMap) {
        if (acrValues == null || acrValues.isBlank()) return 0;
        for (String value : acrValues.trim().split("\s+")) {
            Integer level = loaMap != null ? loaMap.get(value) : null;
            if (level == null) {
                try {
                    level = Integer.valueOf(value);
                } catch (NumberFormatException e) {
                    continue;
                }
            }
            if (level >= 1) return Math.min(level, MAX_LEVEL);
        }
        return 0;
    }

    /** The level the authentication session asks for (from the request's acr_values), 0 when it asks for none. Never throws. */
    public static int requested(AuthenticationSessionModel authSession) {
        try {
            if (authSession == null) return 0;
            String values = authSession.getClientNote(OAuth2Constants.ACR_VALUES);
            ClientModel client = authSession.getClient();
            return requested(values, client != null ? AcrUtils.getAcrLoaMap(client) : null);
        } catch (RuntimeException e) {
            LOG.debugf("[Humifortis] acr_values unreadable: %s", e.getMessage());
            return 0;
        }
    }

    /** The level to record for a decision's achieved assurance note, or 0. */
    static int achieved(String note) {
        if (note == null || note.isBlank()) return 0;
        try {
            return Math.max(0, Math.min(Integer.parseInt(note.trim()), MAX_LEVEL));
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    /**
     * Records the level of the completed step-up as Keycloak's level of authentication. Called after the router's factor was
     * validated; does nothing unless the flow step succeeded. Never throws: the sign-in is already decided.
     */
    public static void recordIfSucceeded(AuthenticationFlowContext context) {
        try {
            if (context.getStatus() != FlowStatus.SUCCESS) return;
            AuthenticationSessionModel as = context.getAuthenticationSession();
            int level = achieved(as.getAuthNote(NOTE_ACHIEVED_LEVEL));
            if (level < 1) return;
            new AcrStore(context.getSession(), as).setLevelAuthenticated(level);
        } catch (RuntimeException e) {
            LOG.debugf("[Humifortis] the level of authentication could not be recorded: %s", e.getMessage());
        }
    }
}
