package tech.humifortis.keycloak.token;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.RefreshToken;

/**
 * What the connector knows about a refresh token and why Keycloak refuses one (docs/sso-and-external-idp-e2e.spec.md, P19).
 *
 * <p>Pure functions over the token and the error Keycloak gives; the only read of the request is {@link #decode}.</p>
 */
public final class RefreshTokens {

    /** Keycloak 26.8.1: the token is not the current one and was issued before the last rotation (checked by the token manager). */
    static final String REASON_STALE = "Stale token";
    /** Keycloak 26.8.1: a rotated token presented more often than {@code refreshTokenMaxReuse} allows. */
    static final String REASON_REUSE_EXCEEDED = "Maximum allowed refresh token reuse exceeded";

    public static final String FAILURE_REUSE = "reuse";
    public static final String FAILURE_SESSION_REVOKED = "session_revoked";
    public static final String FAILURE_INVALID = "invalid";

    /** The event type of the reuse of a rotated refresh token. */
    public static final String EVENT_REUSED = "auth_token_refresh_reused";

    private RefreshTokens() {}

    /** True when Keycloak refused the refresh because a rotated refresh token was presented again. */
    public static boolean isReuse(String reason) {
        return REASON_STALE.equals(reason) || REASON_REUSE_EXCEEDED.equals(reason);
    }

    /** Why a refresh was refused, in the product's words: reuse, session_revoked (the session is gone) or invalid. */
    public static String failureOf(String reason) {
        if (isReuse(reason)) return FAILURE_REUSE;
        if (reason != null) {
            String r = reason.toLowerCase(Locale.ROOT);
            if (r.contains("session not active") || r.contains("session not found") || r.contains("client session not active")
                    || r.contains("session doesn't have required client")) {
                return FAILURE_SESSION_REVOKED;
            }
        }
        return FAILURE_INVALID;
    }

    /**
     * The facts of one refresh the rules judge: how long the token lay unused (it was issued at the last refresh), how old the
     * sign-in is, whether it is an offline token, and what kind of client presents it.
     *
     * @param nowSec       the time of the refresh, epoch seconds
     * @param iat          when the token presented was issued, null when unknown
     * @param authTime     when the person signed in, null when unknown
     * @param offline      an offline token (offline_access)
     * @param publicClient a browser or device application, not an application server
     */
    public static Map<String, String> contextOf(long nowSec, Long iat, Long authTime, boolean offline, boolean publicClient) {
        Map<String, String> out = new LinkedHashMap<>();
        if (iat != null && iat > 0) out.put("refresh_idle_hours", String.valueOf(Math.max(0, nowSec - iat) / 3600));
        if (authTime != null && authTime > 0) out.put("refresh_age_hours", String.valueOf(Math.max(0, nowSec - authTime) / 3600));
        out.put("refresh_offline", String.valueOf(offline));
        out.put("client_type", publicClient ? "public" : "confidential");
        return out;
    }

    /** The refresh token of the current token request, or null (not a refresh request, or an unreadable token). */
    public static RefreshToken decode(KeycloakSession session) {
        try {
            var request = session.getContext().getHttpRequest();
            if (request == null || request.getDecodedFormParameters() == null) return null;
            String token = request.getDecodedFormParameters().getFirst("refresh_token");
            RefreshToken decoded = token != null ? session.tokens().decode(token, RefreshToken.class) : null;
            return decoded != null && decoded.getSubject() != null ? decoded : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** Offline tokens are of type Offline in Keycloak. */
    public static boolean isOffline(RefreshToken token) {
        return token != null && isOfflineType(token.getType());
    }

    static boolean isOfflineType(String type) {
        return "Offline".equals(type);
    }
}
