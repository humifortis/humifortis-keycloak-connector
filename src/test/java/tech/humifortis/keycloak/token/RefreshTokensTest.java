package tech.humifortis.keycloak.token;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;

import org.junit.jupiter.api.Test;

class RefreshTokensTest {

    @Test
    void aRotatedTokenPresentedAgainIsReuse() {
        assertTrue(RefreshTokens.isReuse("Stale token"));
        assertTrue(RefreshTokens.isReuse("Maximum allowed refresh token reuse exceeded"));
        assertEquals("reuse", RefreshTokens.failureOf("Stale token"));
    }

    @Test
    void anExpiredOrUnknownTokenIsNotReuse() {
        assertFalse(RefreshTokens.isReuse("Token is not active"));
        assertFalse(RefreshTokens.isReuse(null));
        assertEquals("invalid", RefreshTokens.failureOf("Invalid refresh token"));
        assertEquals("invalid", RefreshTokens.failureOf(null));
    }

    @Test
    void aTokenOfARevokedSessionIsToldApart() {
        assertEquals("session_revoked", RefreshTokens.failureOf("Session not active"));
        assertEquals("session_revoked", RefreshTokens.failureOf("Offline session not active"));
        assertEquals("session_revoked", RefreshTokens.failureOf("Client session not active"));
        assertEquals("session_revoked", RefreshTokens.failureOf("Offline user session not found"));
    }

    @Test
    void theContextStatesIdleAgeKindAndClient() {
        long now = 10_000_000L;
        Map<String, String> ctx = RefreshTokens.contextOf(now, now - 8 * 24 * 3600L, now - 30 * 24 * 3600L, true, true);
        assertEquals("192", ctx.get("refresh_idle_hours"));
        assertEquals("720", ctx.get("refresh_age_hours"));
        assertEquals("true", ctx.get("refresh_offline"));
        assertEquals("public", ctx.get("client_type"));
    }

    @Test
    void anUnknownTimeIsAbsentNeverZero() {
        Map<String, String> ctx = RefreshTokens.contextOf(1_000_000L, null, null, false, false);
        assertFalse(ctx.containsKey("refresh_idle_hours"));
        assertFalse(ctx.containsKey("refresh_age_hours"));
        assertEquals("confidential", ctx.get("client_type"));
        assertEquals("false", ctx.get("refresh_offline"));
    }

    @Test
    void aClockAheadOfTheTokenNeverGivesANegativeIdle() {
        Map<String, String> ctx = RefreshTokens.contextOf(100L, 200L, 300L, false, true);
        assertEquals("0", ctx.get("refresh_idle_hours"));
    }

    @Test
    void offlineTokensAreOfTypeOffline() {
        assertTrue(RefreshTokens.isOfflineType("Offline"));
        assertFalse(RefreshTokens.isOfflineType("Refresh"));
        assertFalse(RefreshTokens.isOffline(null));
    }
}
