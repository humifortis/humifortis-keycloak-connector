package tech.humifortis.keycloak.token;

import java.util.LinkedHashMap;
import java.util.Map;

import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.ClientPolicyExecutorConfigurationRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.context.TokenExchangeRequestContext;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProvider;

import tech.humifortis.keycloak.serviceaccount.ServiceAccountRiskExecutor;

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
        RealmModel realm = session.getContext().getRealm();
        ClientModel caller = session.getContext().getClient();
        String scope = params.getFirst("scope");
        String audience = params.getFirst("audience");
        String flow = token.getSessionId();
        ServiceAccountRiskExecutor machines = new ServiceAccountRiskExecutor(session);

        ClientModel subjectMachine = machineOf(realm, user);
        if (subjectMachine != null) {
            // MA-2 / MA-4: the token is a machine's. It is decided as that machine, the audience judged like a scope; a
            // different client presenting it is a machine acting for another machine, and is decided too.
            ClientModel actor = caller != null && !caller.getId().equals(subjectMachine.getId()) ? caller : null;
            machines.executeExchange(subjectMachine, flow, scope, audience, actor != null ? actor.getClientId() : null);
            if (actor != null && actor.isServiceAccountsEnabled()) {
                machines.executeExchange(actor, flow, scope, audience, subjectMachine.getClientId());
            }
            return;
        }
        // a person's token. A machine presenting it acts for her (MA-3): the decision carries both, and the machine is decided too.
        boolean machineCaller = caller != null && caller.isServiceAccountsEnabled();
        Map<String, String> more = machineCaller ? actingMachine(realm, caller) : null;
        // who acts for whom (P21): the chain of the subject token, its depth, a loop, an actor the realm does not know
        Map<String, String> chain = DelegationChain.of(token.getOtherClaims()).facts(actor -> realm.getClientByClientId(actor) != null);
        if (!chain.isEmpty() && more != null) chain.putAll(more);
        TokenRiskStage.Verdict verdict = chain.isEmpty()
                ? TokenRiskStage.evaluate(session, DECISION_STAGE, user, flow, more)
                : TokenRiskStage.evaluate(session, DECISION_STAGE, user, flow, "auth_token_exchange",
                        new tech.humifortis.keycloak.auth.StageContext(chain, true, flow));
        if (verdict != null && verdict.refuse()) {
            throw new ClientPolicyException("access_denied", TokenRiskStage.DENY_DESCRIPTION);
        }
        if (machineCaller) machines.executeExchange(caller, flow, scope, audience, null);
    }

    /** The client behind a service-account user (null for a person). */
    private static ClientModel machineOf(RealmModel realm, UserModel user) {
        if (realm == null || user == null || user.getServiceAccountClientLink() == null) return null;
        return realm.getClientById(user.getServiceAccountClientLink());
    }

    /** What a decision about a person names of the machine acting for her. */
    static Map<String, String> actingMachine(RealmModel realm, ClientModel caller) {
        Map<String, String> more = new LinkedHashMap<>();
        more.put("actor_client_id", caller.getClientId());
        more.put("actor", ServiceAccountRiskExecutor.entityId(realm, caller));
        return more;
    }
}
