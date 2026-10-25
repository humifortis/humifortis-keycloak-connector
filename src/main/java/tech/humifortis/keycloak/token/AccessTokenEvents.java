package tech.humifortis.keycloak.token;

import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.AccessToken;

/**
 * Keycloak's user-info error event names neither the person nor the session: the access token of the request does. A key-bound
 * token presented without its proof would otherwise be refused anonymously, and the theft of the token would be nobody's.
 * The token is decoded by Keycloak, which checks its signature with the realm keys: an unsigned or forged token gives nobody.
 */
public final class AccessTokenEvents {

    private AccessTokenEvents() {}

    /** Gives a user-info error event the person and the session of the access token of the request, when the event has none. */
    public static void attribute(KeycloakSession session, Event event) {
        if (event.getType() != EventType.USER_INFO_REQUEST_ERROR) return;
        if (event.getUserId() != null && !event.getUserId().isBlank()) return;
        AccessToken token = decode(session);
        if (token == null) return;
        event.setUserId(token.getSubject());
        if (token.getSessionId() != null) event.setSessionId(token.getSessionId());
    }

    /** The access token of the current request ("Authorization: DPoP|Bearer <token>"), or null (none, or unreadable). */
    static AccessToken decode(KeycloakSession session) {
        try {
            var request = session.getContext().getHttpRequest();
            if (request == null) return null;
            return decodeHeader(request.getHttpHeaders().getHeaderString("Authorization"), session);
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static AccessToken decodeHeader(String header, KeycloakSession session) {
        String token = tokenOf(header);
        if (token == null) return null;
        AccessToken decoded = session.tokens().decode(token, AccessToken.class);
        return decoded != null && decoded.getSubject() != null ? decoded : null;
    }

    /** The token of an Authorization header whose scheme is Bearer or DPoP, or null. */
    static String tokenOf(String header) {
        if (header == null) return null;
        String[] parts = header.trim().split("\s+", 2);
        if (parts.length != 2) return null;
        String scheme = parts[0];
        if (!scheme.equalsIgnoreCase("Bearer") && !scheme.equalsIgnoreCase("DPoP")) return null;
        return parts[1].isBlank() ? null : parts[1].trim();
    }
}
