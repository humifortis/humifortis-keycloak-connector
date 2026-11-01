package tech.humifortis.keycloak.token;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.grants.ciba.channel.CIBAAuthenticationRequest;
import org.keycloak.protocol.oidc.grants.ciba.clientpolicy.context.CIBAContext;
import org.keycloak.representations.idm.ClientPolicyExecutorConfigurationRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProvider;

/**
 * The risk stage of CIBA, the decoupled sign-in (docs/sso-and-external-idp-e2e.spec.md, P12, DV-5): an application asks for a
 * named person, Keycloak asks the person's phone through its authentication channel, and the person approves there. No
 * browser page exists, so the decision cannot ride on a sign-in form: it is taken here, at the two moments a refusal still
 * costs nothing.
 *
 * <ul>
 *   <li>{@code ciba_request}: when the application starts the request, before the phone is bothered. A person whose risk is
 *       critical gets {@code access_denied} at once.</li>
 *   <li>{@code ciba_token}: when the application collects the token, after the person approved. The risk may have risen in
 *       between; a deny or a step-up refuses the token (nothing can be asked at a token endpoint, as for a refresh).</li>
 * </ul>
 *
 * Attached to a realm by a client profile and a client policy (INSTALLATION.md); without them nothing changes. Fail-open like
 * the other token stages ({@link TokenRiskStage}).
 */
public class CibaRiskExecutor implements ClientPolicyExecutorProvider<ClientPolicyExecutorConfigurationRepresentation> {

    public static final String STAGE_REQUEST = "ciba_request";
    public static final String STAGE_TOKEN = "ciba_token";

    private final KeycloakSession session;

    public CibaRiskExecutor(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public String getProviderId() {
        return CibaRiskExecutorFactory.PROVIDER_ID;
    }

    /** The stage name of a client-policy event, or null when this executor does not act on it. */
    static String stageOf(ClientPolicyEvent event) {
        if (event == ClientPolicyEvent.BACKCHANNEL_AUTHENTICATION_REQUEST) return STAGE_REQUEST;
        if (event == ClientPolicyEvent.BACKCHANNEL_TOKEN_REQUEST) return STAGE_TOKEN;
        return null;
    }

    @Override
    public void executeOnEvent(ClientPolicyContext context) throws ClientPolicyException {
        String stage = stageOf(context.getEvent());
        if (stage == null || !(context instanceof CIBAContext ciba)) return;
        CIBAAuthenticationRequest request = ciba.getParsedRequest();
        UserModel user = request != null ? request.getUser() : null;
        if (user == null) return; // Keycloak refuses a request for nobody itself
        String flowId = request.getAuthResultId();
        TokenRiskStage.Verdict verdict = TokenRiskStage.evaluate(session, stage, user, flowId);
        if (verdict != null && verdict.refuse()) {
            throw new ClientPolicyException("access_denied", TokenRiskStage.DENY_DESCRIPTION);
        }
    }
}
