package tech.humifortis.keycloak.token;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.representations.RefreshToken;
import org.keycloak.representations.idm.ClientPolicyExecutorConfigurationRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.context.TokenRefreshContext;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProvider;

/**
 * The risk stage of a refresh-token request: it runs before Keycloak touches the session, asks Humifortis for the
 * decision about the person the refresh token belongs to, and refuses the refresh when the decision is a deny or a
 * step-up ({@link TokenRiskStage}). The client then sends the person through the browser flow again, where the decision
 * is enforced with a page. It is attached to a realm by a client profile and a client policy (INSTALLATION.md);
 * without them nothing changes.
 */
public class TokenRefreshRiskExecutor implements ClientPolicyExecutorProvider<ClientPolicyExecutorConfigurationRepresentation> {

    public static final String DECISION_STAGE = "token_refresh";

    private final KeycloakSession session;

    public TokenRefreshRiskExecutor(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public String getProviderId() {
        return TokenRefreshRiskExecutorFactory.PROVIDER_ID;
    }

    @Override
    public void executeOnEvent(ClientPolicyContext context) throws ClientPolicyException {
        if (context.getEvent() != ClientPolicyEvent.TOKEN_REFRESH || !(context instanceof TokenRefreshContext refresh)) return;
        if (refresh.getParams() == null) return;
        String token = refresh.getParams().getFirst("refresh_token");
        RefreshToken refreshToken;
        UserModel user;
        try {
            refreshToken = token != null ? session.tokens().decode(token, RefreshToken.class) : null;
            if (refreshToken == null || refreshToken.getSubject() == null) return; // Keycloak rejects it itself
            user = session.users().getUserById(session.getContext().getRealm(), refreshToken.getSubject());
        } catch (RuntimeException e) {
            return; // an unreadable token is Keycloak's to refuse
        }
        TokenRiskStage.Verdict verdict = TokenRiskStage.evaluate(session, DECISION_STAGE, user, refreshToken.getSessionId());
        if (verdict != null && verdict.refuse()) {
            throw new ClientPolicyException("invalid_grant", TokenRiskStage.DENY_DESCRIPTION);
        }
    }
}
