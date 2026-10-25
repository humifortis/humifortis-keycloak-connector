package tech.humifortis.keycloak.auth;

import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.PostBrokerLoginConstants;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.stream.Collectors;

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

    /** Keycloak's note, set by the first broker login flow when it CREATES the account (otherwise an existing one was linked). */
    static final String NOTE_REGISTERED_NEW_USER = "BROKER_REGISTERED_NEW_USER";

    /**
     * Whether this first broker login linked an EXISTING account of the realm ("true") or created a new one ("false"); null
     * when the question does not apply (no provider, or not the first sign-in through it). Which accounts may be linked is the
     * realm's first broker login flow's decision (verification by e-mail or password, or an automatic link); this only reports it.
     */
    static String accountLinkedOf(AuthenticationSessionModel as) {
        if (LOCAL.equals(identityProvider(as)) || !firstBrokerLogin(as)) return null;
        return String.valueOf(!"true".equals(as.getAuthNote(NOTE_REGISTERED_NEW_USER)));
    }

    /** Whether the realm trusts the e-mail this provider asserts ("true" / "false"), null for a sign-in with no provider. */
    static String emailTrustedOf(AuthenticationSessionModel as, RealmModel realm) {
        String alias = identityProvider(as);
        if (LOCAL.equals(alias) || realm == null) return null;
        IdentityProviderModel provider = realm.getIdentityProviderByAlias(alias);
        return provider == null || provider.isTrustEmail() == null ? null : String.valueOf(provider.isTrustEmail());
    }

    /**
     * Whether the provider asserted a multi-factor sign-in in the ID token ({@code amr} / {@code acr}) or the SAML assertion:
     * "true", "false" when it described the sign-in and did not, null when it said nothing or there is no provider.
     */
    static String assertedMfaOf(AuthenticationSessionModel as) {
        SerializedBrokeredIdentityContext ctx = brokered(as);
        if (ctx == null || ctx.getContextData() == null) return null;
        Boolean asserted = null;
        var token = ctx.getContextData().get("VALIDATED_ID_TOKEN");
        if (token != null) asserted = ProviderAssertion.fromIdToken(token.getData());
        var statement = ctx.getContextData().get("SAML_AUTHN_STATEMENT");
        if (asserted == null && statement != null) asserted = ProviderAssertion.fromSamlAuthnStatement(statement.getData());
        return asserted == null ? null : asserted.toString();
    }

    /** The aliases of every identity provider linked to the account, sorted and comma-separated; null when it has none. */
    static String linkedProvidersOf(KeycloakSession session, RealmModel realm, UserModel user) {
        if (session == null || realm == null || user == null) return null;
        try {
            String aliases = session.users().getFederatedIdentitiesStream(realm, user)
                    .map(FederatedIdentityModel::getIdentityProvider).filter(a -> a != null && !a.isBlank())
                    .sorted().collect(Collectors.joining(","));
            return aliases.isEmpty() ? null : aliases;
        } catch (RuntimeException e) {
            return null;
        }
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
