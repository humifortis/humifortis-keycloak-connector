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
    /** The event the stage's evaluation is: a refresh, judged by the rules of a sign-in on the network and by its own on the token. */
    public static final String EVENT_TYPE = "auth_token_refresh";

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
        // a service account that holds a refresh token (a client configured to receive one) is decided as the machine it is (MA-6)
        var realm = session.getContext().getRealm();
        if (user != null && user.getServiceAccountClientLink() != null) {
            var machine = realm.getClientById(user.getServiceAccountClientLink());
            if (machine != null) new tech.humifortis.keycloak.serviceaccount.ServiceAccountRiskExecutor(session).executeRefresh(machine, refreshToken.getSessionId());
            return;
        }
        // a refresh is judged as its own touch: how long the token lay unused, and from where. A confidential client refreshes
        // from its own server, so the request's address is not the person's and is not sent.
        var client = session.getContext().getClient();
        boolean publicClient = client != null && client.isPublicClient();
        var facts = RefreshTokens.contextOf(System.currentTimeMillis() / 1000L, refreshToken.getIat(), refreshToken.getAuth_time(),
                RefreshTokens.isOffline(refreshToken), publicClient);
        TokenRiskStage.Verdict verdict = TokenRiskStage.evaluate(session, DECISION_STAGE, user, refreshToken.getSessionId(), EVENT_TYPE,
                new tech.humifortis.keycloak.auth.StageContext(facts, publicClient, refreshToken.getSessionId()));
        if (verdict != null && verdict.refuse()) {
            throw new ClientPolicyException("invalid_grant", TokenRiskStage.DENY_DESCRIPTION);
        }
    }
}
