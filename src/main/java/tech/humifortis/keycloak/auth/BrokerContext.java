package tech.humifortis.keycloak.auth;

import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.PostBrokerLoginConstants;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * The identity provider a login came through. Keycloak keeps the brokered identity in the authentication session:
 * under {@code PBL_BROKERED_IDENTITY_CONTEXT} in a post-login flow of the provider, under {@code BROKERED_CONTEXT} in
 * the first broker login flow. A password login has neither: its provider is {@code local}.
 */
final class BrokerContext {

    static final String LOCAL = "local";

    private BrokerContext() {}

    /** The alias of the identity provider that authenticated the person, or {@code local}. */
    static String identityProvider(AuthenticationSessionModel as) {
        SerializedBrokeredIdentityContext ctx = brokered(as);
        String alias = ctx != null ? ctx.getIdentityProviderId() : null;
        return alias != null && !alias.isBlank() ? alias : LOCAL;
    }

    /** True while the person is in the first login with this provider (the account was just created or linked). */
    static boolean firstBrokerLogin(AuthenticationSessionModel as) {
        if (as == null) return false;
        return as.getAuthNote(AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE) != null
                || "true".equals(as.getAuthNote(PostBrokerLoginConstants.PBL_AFTER_FIRST_BROKER_LOGIN));
    }

    /** "true" / "false" for a brokered sign-in (its first one or a later one), null for a sign-in with no provider. */
    static String firstBrokerLoginOf(AuthenticationSessionModel as) {
        if (LOCAL.equals(identityProvider(as))) return null;
        return String.valueOf(firstBrokerLogin(as));
    }

    private static SerializedBrokeredIdentityContext brokered(AuthenticationSessionModel as) {
        if (as == null) return null;
        for (String note : new String[] {PostBrokerLoginConstants.PBL_BROKERED_IDENTITY_CONTEXT,
                AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE}) {
            try {
                SerializedBrokeredIdentityContext ctx = SerializedBrokeredIdentityContext.readFromAuthenticationSession(as, note);
                if (ctx != null) return ctx;
            } catch (RuntimeException e) {
                // an unreadable note is not a brokered login we can name: fall through to the next, then to local
            }
        }
        return null;
    }
}
