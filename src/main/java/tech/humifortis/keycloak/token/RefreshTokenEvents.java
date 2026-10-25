package tech.humifortis.keycloak.token;

import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.RefreshToken;

/**
 * Keycloak's refresh error event names the client and the error but not the person: the token that was refused does. Without
 * the person the event would be filed under an anonymous account and the theft of her token would be nobody's.
 */
public final class RefreshTokenEvents {

    private RefreshTokenEvents() {}

    /** Gives a refresh error event the person and the session of the refresh token of the request, when the event has none. */
    public static void attribute(KeycloakSession session, Event event) {
        if (event.getType() != EventType.REFRESH_TOKEN_ERROR) return;
        boolean noUser = event.getUserId() == null || event.getUserId().isBlank();
        boolean noSession = event.getSessionId() == null || event.getSessionId().isBlank();
        if (!noUser && !noSession) return;
        RefreshToken token = RefreshTokens.decode(session);
        if (token == null) return;
        if (noUser) event.setUserId(token.getSubject());
        if (noSession && token.getSessionId() != null) event.setSessionId(token.getSessionId());
    }
}
