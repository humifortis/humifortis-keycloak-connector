package tech.humifortis.keycloak.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.net.http.HttpRequest;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Flow;
import java.util.stream.Stream;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.Answers;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import tech.humifortis.keycloak.client.CircuitBreaker;
import tech.humifortis.keycloak.client.HumifortisTransport;
import tech.humifortis.keycloak.client.SaasConfig;
import tech.humifortis.keycloak.model.Risk;

class HumifortisRiskEvaluatorDetailedTest {

    @AfterEach
    void clear() { FallbackPolicy.clearCache(); }

    @Test
    void evaluateDetailed_whenKnownUserIsNull_returnsFallbackWithoutDecision() {
        KeycloakSession session = mock(KeycloakSession.class);
        RealmModel realm = mock(RealmModel.class);

        HumifortisRiskEvaluator.EvaluationResult result =
                new HumifortisRiskEvaluator(session).evaluateDetailed(realm, null, "flow-1");

        assertEquals(Risk.Score.NONE, result.risk().getScore());
        assertEquals("Humifortis unavailable - fail open", result.risk().getReason().orElseThrow());
        assertNull(result.decision());
        assertEquals("null_user", result.fallbackReason());
    }

    @Test
    void endpointPolicy_rejectsPlainHttpWithoutExplicitOverride() {
        assertEquals(false, HumifortisRiskEvaluator.isAllowedEndpoint("http://hf-proxy:80", null));
        assertEquals(false, HumifortisRiskEvaluator.isAllowedEndpoint("http://hf-proxy:80", "false"));
    }

    @Test
    void endpointPolicy_allowsHttpsAndExplicitTestHttpOverride() {
        assertEquals(true, HumifortisRiskEvaluator.isAllowedEndpoint("https://core.example", null));
        assertEquals(true, HumifortisRiskEvaluator.isAllowedEndpoint("http://hf-proxy:80", "true"));
        assertEquals(false, HumifortisRiskEvaluator.isAllowedEndpoint("ftp://core.example", "true"));
    }

    @Test
    void missingApiKeyIsAFallbackWithItsReason() {
        SaasConfig noKey = new SaasConfig(Map.of());
        RealmModel realm = mock(RealmModel.class);
        when(realm.getName()).thenReturn("demo");
        UserModel user = mock(UserModel.class);
        HumifortisRiskEvaluator.EvaluationResult r = new HumifortisRiskEvaluator(mock(KeycloakSession.class), noKey, stub(new ArrayList<>()))
                .evaluateDetailed(realm, user, "f");
        assertNull(r.decision());
        assertEquals("missing_api_key", r.fallbackReason());
    }

    @Test
    void retriesThenAppliesTheDecision_sendsApplicationContext_andCachesTheFallbackPolicy() {
        List<String> bodies = new ArrayList<>();
        Deque<Integer> statuses = new ArrayDeque<>(List.of(503, 200));
        HumifortisTransport transport = new HumifortisTransport(req -> {
            bodies.add(body(req));
            int status = statuses.isEmpty() ? 200 : statuses.pollFirst();
            return new HumifortisTransport.Response(status, status == 200
                    ? "{\"risk_level\":\"MEDIUM\",\"action\":\"REQUIRE_MFA\",\"mode\":\"enforce\",\"fallback_policy\":{\"default\":\"step_up\",\"privileged\":\"deny\"}}"
                    : "", null);
        }, CircuitBreaker.standard("t"), System::currentTimeMillis, ms -> { }, b -> 0);

        SaasConfig config = new SaasConfig(Map.of("HUMIFORTIS_API_KEY", "k", "HUMIFORTIS_API_URL", "https://api.example"));
        KeycloakSession session = mock(KeycloakSession.class, Answers.RETURNS_DEEP_STUBS);
        AuthenticationSessionModel as = mock(AuthenticationSessionModel.class);
        ClientModel client = mock(ClientModel.class);
        when(client.getClientId()).thenReturn("finance-portal");
        when(as.getClient()).thenReturn(client);
        when(as.getRedirectUri()).thenReturn("https://finance.example/cb");
        when(session.getContext().getAuthenticationSession()).thenReturn(as);
        when(session.getContext().getConnection().getRemoteAddr()).thenReturn("203.0.113.7");
        when(session.getAttribute(org.mockito.ArgumentMatchers.anyString())).thenReturn(null);
        RealmModel realm = mock(RealmModel.class);
        when(realm.getName()).thenReturn("demo");
        UserModel user = mock(UserModel.class);
        when(user.getId()).thenReturn("u1");
        SubjectCredentialManager creds = mock(SubjectCredentialManager.class);
        when(user.credentialManager()).thenReturn(creds);
        when(creds.getStoredCredentialsStream()).thenAnswer(i -> Stream.empty());
        when(user.getRoleMappingsStream()).thenAnswer(i -> Stream.empty());
        when(user.getGroupsStream()).thenAnswer(i -> Stream.empty());
        when(session.sessions().getUserSessionsStream(realm, user)).thenAnswer(i -> Stream.empty());

        HumifortisRiskEvaluator.EvaluationResult r = new HumifortisRiskEvaluator(session, config, transport).evaluateDetailed(realm, user, "flow-9");

        assertNotNull(r.decision(), "the second attempt answered");
        assertNull(r.fallbackReason());
        assertEquals("REQUIRE_MFA", r.decision().action);
        assertEquals(2, bodies.size());
        JsonObject meta = JsonParser.parseString(bodies.get(1)).getAsJsonObject().getAsJsonObject("event").getAsJsonObject("metadata");
        assertEquals("finance-portal", meta.get("client_id").getAsString());
        assertEquals("https://finance.example/cb", meta.get("redirect_uri").getAsString());
        assertEquals("203.0.113.7", meta.get("ip").getAsString());
        assertEquals("keycloak_connection", meta.get("ip_source").getAsString());
        assertTrue(meta.has("proxy_headers_mode"));
        assertEquals("false", meta.get("is_privileged").getAsString());
        // the tenant policy is remembered for the next outage
        assertEquals(FallbackPolicy.Outcome.STEP_UP, FallbackPolicy.resolve(null, "demo", false, true).outcome());
        assertEquals("tenant_cache", FallbackPolicy.resolve(null, "demo", false, true).source());
    }

    private static HumifortisTransport stub(List<String> bodies) {
        return new HumifortisTransport(req -> {
            bodies.add(body(req));
            return new HumifortisTransport.Response(200, "{}", null);
        }, CircuitBreaker.standard("t"), System::currentTimeMillis, ms -> { }, b -> 0);
    }

    /** Reads a request body (the publisher is consumed synchronously). */
    static String body(HttpRequest req) {
        StringBuilder sb = new StringBuilder();
        req.bodyPublisher().orElseThrow().subscribe(new Flow.Subscriber<>() {
            public void onSubscribe(Flow.Subscription s) { s.request(Long.MAX_VALUE); }
            public void onNext(ByteBuffer item) { sb.append(StandardCharsets.UTF_8.decode(item)); }
            public void onError(Throwable t) { }
            public void onComplete() { }
        });
        return sb.toString();
    }
}
