package tech.humifortis.keycloak.serviceaccount;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.keycloak.events.EventType;

class ServiceAccountContextTest {

    private static final Instant NOW = Instant.parse("2026-10-05T12:00:00Z");

    private static Map<String, String> attrs(String... kv) {
        Map<String, String> m = new HashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put(kv[i], kv[i + 1]);
        return m;
    }

    @Test
    void onlyClientCredentialsEventsAreServiceAccountEvents() {
        assertTrue(ServiceAccountContext.isClientCredentialsEvent(EventType.CLIENT_LOGIN));
        assertTrue(ServiceAccountContext.isClientCredentialsEvent(EventType.CLIENT_LOGIN_ERROR));
        assertFalse(ServiceAccountContext.isClientCredentialsEvent(EventType.LOGIN));
        assertFalse(ServiceAccountContext.isClientCredentialsEvent(EventType.LOGIN_ERROR));
        assertFalse(ServiceAccountContext.isClientCredentialsEvent(EventType.CODE_TO_TOKEN));
    }

    @Test
    void aClientWithoutDeclaredExpectationsSendsOnlyTheScopesItRequested() {
        Map<String, String> out = ServiceAccountContext.resolve(attrs(), "203.0.113.5", "profile email", NOW);
        assertEquals(Map.of(ServiceAccountContext.KEY_REQUESTED_SCOPES, "email,profile"), out,
                "nothing is judged against a guess: undeclared inputs are not sent");
        assertTrue(ServiceAccountContext.resolve(null, null, null, NOW).isEmpty());
    }

    @Test
    void scopesAreSortedDeduplicatedAndCommaSeparated() {
        assertEquals("a,b,c", ServiceAccountContext.joinScopes(" c  b,a a "));
        assertNull(ServiceAccountContext.joinScopes("  "));
        assertNull(ServiceAccountContext.joinScopes(null));
    }

    @Test
    void baselineScopesAreForwardedAsTheHistoricalBaseline() {
        Map<String, String> out = ServiceAccountContext.resolve(
                attrs(ServiceAccountContext.ATTR_BASELINE_SCOPES, "profile, email"), null, "email profile address", NOW);
        assertEquals("email,profile", out.get(ServiceAccountContext.KEY_HISTORICAL_SCOPES));
        assertEquals("address,email,profile", out.get(ServiceAccountContext.KEY_REQUESTED_SCOPES));
    }

    @Test
    void theAllowlistAcceptsAddressesAndCidrsInBothFamilies() {
        String list = "198.51.100.7, 203.0.113.0/24 2001:db8::/32";
        assertEquals(Boolean.TRUE, ServiceAccountContext.matchesAllowlist("198.51.100.7", list));
        assertEquals(Boolean.TRUE, ServiceAccountContext.matchesAllowlist("203.0.113.200", list));
        assertEquals(Boolean.TRUE, ServiceAccountContext.matchesAllowlist("2001:db8:1::5", list));
        assertEquals(Boolean.FALSE, ServiceAccountContext.matchesAllowlist("198.51.100.8", list));
        assertEquals(Boolean.FALSE, ServiceAccountContext.matchesAllowlist("203.0.114.1", list));
        assertEquals(Boolean.FALSE, ServiceAccountContext.matchesAllowlist("2001:db9::1", list));
    }

    @Test
    void anOddPrefixLengthIsHonoured() {
        assertEquals(Boolean.TRUE, ServiceAccountContext.matchesAllowlist("10.0.127.255", "10.0.0.0/17"));
        assertEquals(Boolean.FALSE, ServiceAccountContext.matchesAllowlist("10.0.128.0", "10.0.0.0/17"));
        assertEquals(Boolean.TRUE, ServiceAccountContext.matchesAllowlist("8.8.8.8", "0.0.0.0/0"));
    }

    @Test
    void noJudgementWithoutAUsableAllowlistOrSource() {
        assertNull(ServiceAccountContext.matchesAllowlist("203.0.113.5", null));
        assertNull(ServiceAccountContext.matchesAllowlist("203.0.113.5", "  "));
        assertNull(ServiceAccountContext.matchesAllowlist(null, "203.0.113.0/24"));
        assertNull(ServiceAccountContext.matchesAllowlist("not-an-ip", "203.0.113.0/24"));
        // an allowlist with no valid entry must not turn every caller into an intruder
        assertNull(ServiceAccountContext.matchesAllowlist("203.0.113.5", "garbage, 10.0.0.0/99, example.com"));
        // a name is never resolved
        assertNull(ServiceAccountContext.matchesAllowlist("203.0.113.5", "localhost"));
    }

    @Test
    void invalidEntriesAreIgnoredWhileValidOnesStillApply() {
        assertEquals(Boolean.TRUE, ServiceAccountContext.matchesAllowlist("203.0.113.5", "garbage, 203.0.113.0/24"));
        assertEquals(Boolean.FALSE, ServiceAccountContext.matchesAllowlist("198.51.100.1", "garbage, 203.0.113.0/24"));
    }

    @Test
    void theAllowlistVerdictIsForwardedAsABoolean() {
        Map<String, String> attrs = attrs(ServiceAccountContext.ATTR_SOURCE_ALLOWLIST, "203.0.113.0/24");
        assertEquals("true", ServiceAccountContext.resolve(attrs, "203.0.113.9", null, NOW).get(ServiceAccountContext.KEY_SOURCE_ALLOWLIST_MATCH));
        assertEquals("false", ServiceAccountContext.resolve(attrs, "198.51.100.9", null, NOW).get(ServiceAccountContext.KEY_SOURCE_ALLOWLIST_MATCH));
        assertFalse(ServiceAccountContext.resolve(attrs, null, null, NOW).containsKey(ServiceAccountContext.KEY_SOURCE_ALLOWLIST_MATCH));
    }

    @Test
    void theExecutionWindowNeedsBothValidHours() {
        Map<String, String> ok = ServiceAccountContext.resolve(attrs(
                ServiceAccountContext.ATTR_WINDOW_START_HOUR, "22", ServiceAccountContext.ATTR_WINDOW_END_HOUR, "2"), null, null, NOW);
        assertEquals("22", ok.get(ServiceAccountContext.KEY_WINDOW_START_HOUR));
        assertEquals("2", ok.get(ServiceAccountContext.KEY_WINDOW_END_HOUR));

        for (String[] bad : new String[][] {{"22", null}, {null, "2"}, {"24", "2"}, {"-1", "2"}, {"x", "2"}}) {
            Map<String, String> a = new HashMap<>();
            if (bad[0] != null) a.put(ServiceAccountContext.ATTR_WINDOW_START_HOUR, bad[0]);
            if (bad[1] != null) a.put(ServiceAccountContext.ATTR_WINDOW_END_HOUR, bad[1]);
            Map<String, String> out = ServiceAccountContext.resolve(a, null, null, NOW);
            assertFalse(out.containsKey(ServiceAccountContext.KEY_WINDOW_START_HOUR), String.join("/", String.valueOf(bad[0]), String.valueOf(bad[1])));
            assertFalse(out.containsKey(ServiceAccountContext.KEY_WINDOW_END_HOUR));
        }
    }

    @Test
    void credentialAgeIsTheTimeSinceKeycloakCreatedTheSecret() {
        long created = NOW.minusSeconds(120L * 86400 + 3600).getEpochSecond();
        Map<String, String> out = ServiceAccountContext.resolve(attrs(
                ServiceAccountContext.ATTR_SECRET_CREATED, Long.toString(created),
                ServiceAccountContext.ATTR_ROTATION_MAX_AGE_DAYS, "90"), null, null, NOW);
        assertEquals("120", out.get(ServiceAccountContext.KEY_CREDENTIAL_AGE_DAYS));
        assertEquals("90", out.get(ServiceAccountContext.KEY_ROTATION_MAX_AGE_DAYS));
    }

    @Test
    void aSecretCreatedInTheFutureIsNeverNegative() {
        Map<String, String> out = ServiceAccountContext.resolve(attrs(
                ServiceAccountContext.ATTR_SECRET_CREATED, Long.toString(NOW.plusSeconds(86400).getEpochSecond()),
                ServiceAccountContext.ATTR_ROTATION_MAX_AGE_DAYS, "90"), null, null, NOW);
        assertEquals("0", out.get(ServiceAccountContext.KEY_CREDENTIAL_AGE_DAYS));
    }

    @Test
    void theRotationPolicyNeedsAKnownSecretAgeAndAPositiveMaximum() {
        long created = NOW.minusSeconds(86400).getEpochSecond();
        // no policy
        assertFalse(ServiceAccountContext.resolve(attrs(ServiceAccountContext.ATTR_SECRET_CREATED, Long.toString(created)), null, null, NOW)
                .containsKey(ServiceAccountContext.KEY_CREDENTIAL_AGE_DAYS));
        // no secret age (a client that never had a secret)
        assertTrue(ServiceAccountContext.resolve(attrs(ServiceAccountContext.ATTR_ROTATION_MAX_AGE_DAYS, "90"), null, null, NOW).isEmpty());
        // an invalid policy
        for (String bad : new String[] {"0", "-5", "soon", ""}) {
            assertFalse(ServiceAccountContext.resolve(attrs(
                    ServiceAccountContext.ATTR_SECRET_CREATED, Long.toString(created),
                    ServiceAccountContext.ATTR_ROTATION_MAX_AGE_DAYS, bad), null, null, NOW)
                    .containsKey(ServiceAccountContext.KEY_ROTATION_MAX_AGE_DAYS), bad);
        }
        // a corrupt creation time
        assertTrue(ServiceAccountContext.resolve(attrs(
                ServiceAccountContext.ATTR_SECRET_CREATED, "yesterday",
                ServiceAccountContext.ATTR_ROTATION_MAX_AGE_DAYS, "90"), null, null, NOW).isEmpty());
    }

    @Test
    void everyProducedKeyIsDeclaredForTheMapper() {
        long created = NOW.minusSeconds(100L * 86400).getEpochSecond();
        Map<String, String> out = ServiceAccountContext.resolve(attrs(
                ServiceAccountContext.ATTR_SOURCE_ALLOWLIST, "10.0.0.0/8",
                ServiceAccountContext.ATTR_BASELINE_SCOPES, "profile",
                ServiceAccountContext.ATTR_WINDOW_START_HOUR, "1", ServiceAccountContext.ATTR_WINDOW_END_HOUR, "5",
                ServiceAccountContext.ATTR_SECRET_CREATED, Long.toString(created),
                ServiceAccountContext.ATTR_ROTATION_MAX_AGE_DAYS, "90",
                ServiceAccountContext.ATTR_OWNER, "payments"), "10.1.1.1", "profile", NOW);
        assertEquals(ServiceAccountContext.KEYS, out.keySet());
    }
}