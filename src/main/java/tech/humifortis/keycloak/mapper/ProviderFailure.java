package tech.humifortis.keycloak.mapper;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;

/**
 * A sign-in through an external identity provider that failed on the provider's side (docs/sso-and-external-idp-e2e.spec.md,
 * step 5, ID-7 / ID-8).
 *
 * <p>Keycloak reports it as {@code IDENTITY_PROVIDER_LOGIN_ERROR} with the error {@code identity_provider_login_failure}.
 * That event has <em>no user</em> (the failure happens before the provider says who is signing in), <em>no provider alias</em>
 * and no cause: the same event follows a provider that answers 500, one that refuses the code, one that sends something that
 * is not a token, one that resets the connection and one that answers too late. It is therefore never a failed login of a
 * person: it is a fact about the integration, reported against the integration, naming the provider.</p>
 *
 * <p>The provider is read from where Keycloak itself says it: the browser returns to the realm's broker endpoint,
 * {@code /realms/<realm>/broker/<alias>/endpoint}, and the listener runs during that request. The cause is only in
 * Keycloak's server log, which the event does not carry and a listener cannot read; it is reported as unavailable.</p>
 */
public final class ProviderFailure {

    /** The event type Humifortis receives (a feedback event: audit and operational alert, never scored). */
    public static final String EVENT_TYPE = "identity_provider_login_failed";
    /** The integration the failure is about: the Keycloak connector (core: integration:&lt;product&gt;). */
    public static final String INTEGRATION_ENTITY_ID = "integration:keycloak";
    public static final String INTEGRATION_ENTITY_TYPE = "integration";

    private static final Pattern BROKER_CALLBACK = Pattern.compile("/broker/([^/]+)/(?:endpoint|login)(?:/|$)");

    private ProviderFailure() {}

    /** Whether Keycloak's event is the failure of a provider's sign-in (not a person's, not a first-login-flow error). */
    public static boolean is(EventType type) {
        return type == EventType.IDENTITY_PROVIDER_LOGIN_ERROR;
    }

    /** The provider's alias in a broker callback path, or null when the path is not one. */
    public static String aliasOf(String path) {
        if (path == null) return null;
        Matcher m = BROKER_CALLBACK.matcher(path);
        if (!m.find()) return null;
        String alias = java.net.URLDecoder.decode(m.group(1), java.nio.charset.StandardCharsets.UTF_8);
        return alias.isBlank() ? null : alias;
    }

    /** The alias of the provider of the request being served, or null. Never throws. */
    public static String aliasOfRequest(KeycloakSession session) {
        try {
            var uri = session.getContext().getUri();
            if (uri == null) return null;
            String fromRequest = aliasOf(uri.getRequestUri() != null ? uri.getRequestUri().getPath() : null);
            return fromRequest != null ? fromRequest : aliasOf(uri.getPath());
        } catch (RuntimeException e) {
            return null;
        }
    }
}
