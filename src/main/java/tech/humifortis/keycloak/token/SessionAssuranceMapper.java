package tech.humifortis.keycloak.token;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

import tech.humifortis.keycloak.auth.HumifortisRiskEvaluator;

/**
 * The {@code session_assurance} claim (docs/session-assurance-sas.spec.md 5.2): the session assurance level and the
 * visibility of the session's latest decision, so that an application checks the level an operation needs. It stays apart
 * from {@code acr}, which remains the authentication level of RFC 9470.
 *
 * <p>Opt-in: add the mapper "Humifortis session assurance" to a client scope. A session no decision recorded the axes for
 * carries no claim (never a level 0). The connector notes the axes on the user session at each decision (sign-in, single
 * sign-on reuse, refresh); the mapper only reads them.</p>
 */
public class SessionAssuranceMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    public static final String PROVIDER_ID = "humifortis-session-assurance-mapper";
    public static final String CLAIM = "session_assurance";
    public static final String NOTE_LEVEL = "HUMIFORTIS_SAL";
    public static final String NOTE_VISIBILITY = "HUMIFORTIS_VISIBILITY";

    private static final List<ProviderConfigProperty> CONFIG = new ArrayList<>();

    static {
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(CONFIG, SessionAssuranceMapper.class);
    }

    /** The claim of a session, or null when no decision recorded the axes. */
    public static Map<String, Object> claimOf(UserSessionModel us) {
        if (us == null) return null;
        String level = us.getNote(NOTE_LEVEL);
        if (level == null || level.isBlank()) return null;
        try {
            int sal = Integer.parseInt(level.trim());
            if (sal < 0 || sal > 3) return null;
            Map<String, Object> claim = new LinkedHashMap<>();
            claim.put("level", sal);
            String visibility = us.getNote(NOTE_VISIBILITY);
            if (visibility != null && !visibility.isBlank()) claim.put("visibility", visibility);
            return claim;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /** The axes of a decision as user-session notes: written where a decision about the session is taken. */
    public static Map<String, String> notesOf(HumifortisRiskEvaluator.EvaluateResponse d) {
        Map<String, String> notes = new LinkedHashMap<>();
        if (d == null || d.session_assurance == null || d.session_assurance.level == null) return notes;
        int level = d.session_assurance.level;
        if (level < 0 || level > 3) return notes;
        notes.put(NOTE_LEVEL, String.valueOf(level));
        notes.put(NOTE_VISIBILITY, d.visibility != null && d.visibility.level != null ? d.visibility.level : "");
        return notes;
    }

    /** Notes the axes of a decision on a user session (never throws). */
    public static void record(UserSessionModel us, HumifortisRiskEvaluator.EvaluateResponse d) {
        if (us == null) return;
        try {
            notesOf(d).forEach(us::setNote);
        } catch (RuntimeException e) {
            // the claim is information for the application, never a condition of the decision
        }
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession, KeycloakSession keycloakSession,
                            ClientSessionContext clientSessionCtx) {
        Map<String, Object> claim = claimOf(userSession);
        if (claim != null) token.getOtherClaims().put(CLAIM, claim);
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "Humifortis session assurance";
    }

    @Override
    public String getHelpText() {
        return "Adds the session_assurance claim: the session assurance level (0-3) and the visibility of the session's latest Humifortis decision.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
