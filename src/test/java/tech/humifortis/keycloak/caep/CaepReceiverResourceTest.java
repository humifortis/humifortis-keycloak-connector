package tech.humifortis.keycloak.caep;

import com.google.gson.JsonObject;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import tech.humifortis.keycloak.HumifortisCache;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CaepReceiverResourceTest {

    @Test
    void returns401ForAuthFailure() {
        KeycloakSession keycloakSession = mockSessionWithRealm("realm-a", "realm-a");
        CaepSetValidator validator = new CaepSetValidator(uri -> {
            throw new UnsupportedOperationException();
        }, Clock.systemUTC()) {
            @Override
            public CaepParsedSet validate(String token, CaepConfig config) {
                throw new CaepValidationException(401, "Invalid signature");
            }
        };

        CaepReceiverResource resource = new CaepReceiverResource(
                keycloakSession,
                validator,
                new CaepReplayGuard(HumifortisCache.getInstance()),
                new CaepEventRegistry(),
                Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC));

        Response response = resource.receive("token");
        assertEquals(401, response.getStatus());
    }

    @Test
    void returns200ForReplay() {
        KeycloakSession keycloakSession = mockSessionWithRealm("realm-b", "realm-b");
        CaepSetValidator validator = new CaepSetValidator(uri -> {
            throw new UnsupportedOperationException();
        }, Clock.systemUTC()) {
            @Override
            public CaepParsedSet validate(String token, CaepConfig config) {
                JsonObject events = new JsonObject();
                events.add("session-revoked", new JsonObject());
                return new CaepParsedSet("jti-replay", "iss", Set.of("aud"), Instant.now(), Instant.now().plusSeconds(30), "user", "sid", events);
            }
        };

        CaepReplayGuard guard = new CaepReplayGuard(HumifortisCache.getInstance());
        CaepConfig realmConfig = new CaepConfig(true, "iss", "aud", "jwks", 60, true, 600, true, true, true, true, false);
        guard.isReplay("realm-b", "jti-replay", realmConfig);

        CaepReceiverResource resource = new CaepReceiverResource(
                keycloakSession,
                validator,
                guard,
                new CaepEventRegistry(),
                Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC));
        Response response = resource.receive("token");
        assertEquals(200, response.getStatus());
    }

    @Test
    void replayKeyIsRealmScoped() {
        CaepSetValidator validator = new CaepSetValidator(uri -> {
            throw new UnsupportedOperationException();
        }, Clock.systemUTC()) {
            @Override
            public CaepParsedSet validate(String token, CaepConfig config) {
                JsonObject events = new JsonObject();
                events.add("session-revoked", new JsonObject());
                return new CaepParsedSet("jti-shared", "iss", Set.of("aud"), Instant.now(), Instant.now().plusSeconds(30), "user", "sid", events);
            }
        };

        CaepReplayGuard guard = new CaepReplayGuard(HumifortisCache.getInstance());
        HumifortisCache.getInstance().clear();

        CaepReceiverResource realmOne = new CaepReceiverResource(
                mockSessionWithRealm("realm-1", "realm-1"),
                validator,
                guard,
                new CaepEventRegistry(),
                Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC));
        Response first = realmOne.receive("token");
        assertEquals(200, first.getStatus());
        assertEquals("accepted", ((java.util.Map<?, ?>) first.getEntity()).get("status"));

        CaepReceiverResource realmTwo = new CaepReceiverResource(
                mockSessionWithRealm("realm-2", "realm-2"),
                validator,
                guard,
                new CaepEventRegistry(),
                Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC));
        Response second = realmTwo.receive("token");
        assertEquals(200, second.getStatus());
        assertEquals("accepted", ((java.util.Map<?, ?>) second.getEntity()).get("status"));
    }

    @Test
    void riskLevelChangeEventIsSupported() {
        KeycloakSession keycloakSession = mockSessionWithRealm("realm-risk", "realm-risk");
        CaepSetValidator validator = new CaepSetValidator(uri -> {
            throw new UnsupportedOperationException();
        }, Clock.systemUTC()) {
            @Override
            public CaepParsedSet validate(String token, CaepConfig config) {
                JsonObject events = new JsonObject();
                events.add("https://schemas.openid.net/secevent/caep/event-type/risk-level-change", new JsonObject());
                return new CaepParsedSet("jti-risk", "iss", Set.of("aud"), Instant.now(), Instant.now().plusSeconds(30), "user", "sid", events);
            }
        };

        CaepReceiverResource resource = new CaepReceiverResource(
                keycloakSession,
                validator,
                new CaepReplayGuard(HumifortisCache.getInstance()),
                new CaepEventRegistry(),
                Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC));
        Response response = resource.receive("token");

        assertEquals(200, response.getStatus());
        java.util.Map<?, ?> body = (java.util.Map<?, ?>) response.getEntity();
        assertEquals("accepted", body.get("status"));
        assertEquals("step_up", body.get("action"));
        assertEquals("enforcement_failed", body.get("processing"));
    }

    private KeycloakSession mockSessionWithRealm(String realmId, String realmName) {
        KeycloakSession session = mock(KeycloakSession.class);
        KeycloakContext context = mock(KeycloakContext.class);
        RealmModel realm = mock(RealmModel.class);
        when(realm.getId()).thenReturn(realmId);
        when(realm.getName()).thenReturn(realmName);
        when(realm.getAttribute("hf.caep.enabled")).thenReturn("true");
        when(realm.getAttribute("hf.caep.issuer")).thenReturn("iss");
        when(realm.getAttribute("hf.caep.audience")).thenReturn("aud");
        when(realm.getAttribute("hf.caep.jwksUri")).thenReturn("jwks");
        when(context.getRealm()).thenReturn(realm);
        when(session.getContext()).thenReturn(context);
        return session;
    }
}
