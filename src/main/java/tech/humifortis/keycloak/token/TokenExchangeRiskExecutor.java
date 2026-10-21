package tech.humifortis.keycloak.token;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.ClientPolicyExecutorConfigurationRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.context.TokenExchangeRequestContext;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProvider;

/**
 * The risk stage of a token exchange (RFC 8693): a client trades the person's token for another one (another audience or
 * scope). It asks Humifortis for the decision about the person the subject token belongs to and refuses the exchange on a
 * deny or a step-up ({@link TokenRiskStage}). Attached to a realm by a client profile and a client policy
 * (INSTALLATION.md); without them nothing changes.
 */
public class TokenExchangeRiskExecutor implements ClientPolicyExecutorProvider<ClientPolicyExecutorConfigurationRepresentation> {

    public static final String DECISION_STAGE = "token_exchange";

    private final KeycloakSession session;

    public TokenExchangeRiskExecutor(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public String getProviderId() {
        return TokenExchangeRiskExecutorFactory.PROVIDER_ID;
    }

    @Override
    public void executeOnEvent(ClientPolicyContext context) throws ClientPolicyException {
        if (context.getEvent() != ClientPolicyEvent.TOKEN_EXCHANGE_REQUEST
                || !(context instanceof TokenExchangeRequestContext exchange)) return;
        var params = exchange.getTokenExchangeContext().getFormParams();
        String subjectToken = params != null ? params.getFirst("subject_token") : null;
        AccessToken token;
        UserModel user;
        try {
            token = subjectToken != null ? session.tokens().decode(subjectToken, AccessToken.class) : null;
            if (token == null || token.getSubject() == null) return; // Keycloak rejects it itself
            user = session.users().getUserById(session.getContext().getRealm(), token.getSubject());
        } catch (RuntimeException e) {
            return; // an unreadable token is Keycloak's to refuse
        }
        TokenRiskStage.Verdict verdict = TokenRiskStage.evaluate(session, DECISION_STAGE, user, token.getSessionId());
        if (verdict != null && verdict.refuse()) {
            throw new ClientPolicyException("access_denied", TokenRiskStage.DENY_DESCRIPTION);
        }
    }
}
