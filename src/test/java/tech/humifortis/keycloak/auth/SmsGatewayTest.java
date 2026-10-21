package tech.humifortis.keycloak.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.keycloak.models.UserModel;

import com.sun.net.httpserver.HttpServer;

class SmsGatewayTest {

    private static UserModel user(String phone) {
        UserModel u = mock(UserModel.class);
        when(u.getFirstAttribute("phoneNumber")).thenReturn(phone);
        return u;
    }

    @Test
    void theChannelExistsOnlyWithAnAllowedGatewayUrl() {
        assertNull(SmsGateway.url(Map.of()), "no URL: no channel");
        assertNull(SmsGateway.url(Map.of("HUMIFORTIS_SMS_GATEWAY_URL", "  ")));
        assertEquals("https://sms.example.com/send", SmsGateway.url(Map.of("HUMIFORTIS_SMS_GATEWAY_URL", "https://sms.example.com/send")));
        assertNull(SmsGateway.url(Map.of("HUMIFORTIS_SMS_GATEWAY_URL", "http://sms.example.com/send")), "plain http is refused by default");
        assertEquals("http://sms:8080/sms", SmsGateway.url(Map.of("HUMIFORTIS_SMS_GATEWAY_URL", "http://sms:8080/sms", "HUMIFORTIS_ALLOW_INSECURE_HTTP", "true")));
        assertNull(SmsGateway.url(Map.of("HUMIFORTIS_SMS_GATEWAY_URL", "ftp://x")));
    }

    @Test
    void onlyAnE164NumberIsTexted() {
        Map<String, String> env = Map.of();
        assertEquals("+15145550100", SmsGateway.phoneOf(user("+1 (514) 555-0100"), env), "formatting is stripped");
        assertEquals("+33612345678", SmsGateway.phoneOf(user("+33612345678"), env));
        assertNull(SmsGateway.phoneOf(user("514-555-0100"), env), "no country code: not texted");
        assertNull(SmsGateway.phoneOf(user("+0123456789"), env), "a country code never starts with 0");
        assertNull(SmsGateway.phoneOf(user("+123"), env), "too short");
        assertNull(SmsGateway.phoneOf(user("not a number"), env));
        assertNull(SmsGateway.phoneOf(user(null), env));
        assertNull(SmsGateway.phoneOf(null, env));
    }

    @Test
    void theAttributeIsConfigurable() {
        UserModel u = mock(UserModel.class);
        when(u.getFirstAttribute("mobile")).thenReturn("+15145550100");
        assertEquals("+15145550100", SmsGateway.phoneOf(u, Map.of("HUMIFORTIS_SMS_PHONE_ATTRIBUTE", "mobile")));
        assertNull(SmsGateway.phoneOf(u, Map.of()), "the default attribute is phoneNumber");
    }

    @Test
    void theNumberIsMaskedWhereverItIsShownOrLogged() {
        assertEquals("+1********00", SmsGateway.mask("+15145550100"));
        assertEquals("***", SmsGateway.mask(null));
        assertEquals("***", SmsGateway.mask("+12"));
    }

    @Test
    void sendPostsTheMessageWithTheTokenAndAnyOtherAnswerThanA2xxIsAFailure() throws Exception {
        AtomicReference<String> body = new AtomicReference<>();
        AtomicReference<String> auth = new AtomicReference<>();
        int[] status = {202};
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/sms", ex -> {
            body.set(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            auth.set(ex.getRequestHeaders().getFirst("Authorization"));
            ex.sendResponseHeaders(status[0], -1);
            ex.close();
        });
        server.start();
        try {
            Map<String, String> env = Map.of("HUMIFORTIS_SMS_GATEWAY_URL", "http://127.0.0.1:" + server.getAddress().getPort() + "/sms",
                    "HUMIFORTIS_ALLOW_INSECURE_HTTP", "true", "HUMIFORTIS_SMS_GATEWAY_TOKEN", "s3cret");
            SmsGateway.send(user("+15145550100"), "Your authentication code is: 123456", env);
            assertTrue(body.get().contains("\"to\":\"+15145550100\""), body.get());
            assertTrue(body.get().contains("123456"));
            assertEquals("Bearer s3cret", auth.get());

            status[0] = 500;
            assertThrows(SmsGateway.SmsException.class, () -> SmsGateway.send(user("+15145550100"), "x", env));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void anUnreachableGatewayOrANoNumberIsAFailureNotAnException_ofAnotherKind() {
        Map<String, String> env = Map.of("HUMIFORTIS_SMS_GATEWAY_URL", "http://127.0.0.1:1/sms", "HUMIFORTIS_ALLOW_INSECURE_HTTP", "true");
        assertThrows(SmsGateway.SmsException.class, () -> SmsGateway.send(user("+15145550100"), "x", env));
        assertThrows(SmsGateway.SmsException.class, () -> SmsGateway.send(user(null), "x", env), "no number");
        assertThrows(SmsGateway.SmsException.class, () -> SmsGateway.send(user("+15145550100"), "x", Map.of()), "no gateway");
    }
}
