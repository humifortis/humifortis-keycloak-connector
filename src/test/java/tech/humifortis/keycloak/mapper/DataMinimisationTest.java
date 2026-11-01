package tech.humifortis.keycloak.mapper;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;

import tech.humifortis.keycloak.HumifortisAuditLog;
import tech.humifortis.keycloak.model.HumifortisEvent;

/**
 * PRV-7, the guard: no secret, no code and no password is ever in an event the connector sends, whatever Keycloak put in the
 * details of the event it heard; and the connector's own audit log names a person by a pseudonym.
 */
class DataMinimisationTest {

    private static final Map<String, String> PLANTED = new LinkedHashMap<>();
    static {
        PLANTED.put("password", "Pl4nted-Passw0rd!");
        PLANTED.put("password_new", "Pl4nted-NewPassw0rd!");
        PLANTED.put("code", "246810");
        PLANTED.put("otp", "135790");
        PLANTED.put("totp", "112233");
        PLANTED.put("client_secret", "pl4nted-client-secret");
        PLANTED.put("secret", "pl4nted-secret");
        PLANTED.put("access_token", "pl4nted.access.token");
        PLANTED.put("refresh_token", "pl4nted.refresh.token");
        PLANTED.put("id_token", "pl4nted.id.token");
        PLANTED.put("code_id", "pl4nted-code-id-not-the-flow");
        PLANTED.put("token", "pl4nted.token");
        PLANTED.put("authenticatorData", "pl4nted-authenticator-data");
        PLANTED.put("clientDataJSON", "pl4nted-client-data");
        PLANTED.put("signature", "pl4nted-signature");
    }

    private static final String[] FORBIDDEN_KEY_PARTS = {"password", "secret", "otp", "token", "authenticatordata", "clientdata", "signature"};

    private static Event event(EventType type) {
        Event e = new Event();
        e.setType(type);
        e.setRealmId("realm-1");
        e.setUserId("7f3c1a9e-0000-4000-8000-000000000001");
        e.setClientId("demo-app");
        e.setIpAddress("203.0.113.9");
        e.setSessionId("session-1");
        e.setTime(1_760_000_000_000L);
        Map<String, String> details = new LinkedHashMap<>(PLANTED);
        details.put("username", "alice");
        details.put("email", "alice@example.org");
        details.put("auth_method", "openid-connect");
        e.setDetails(details);
        return e;
    }

    @Test
    void noSecretCodeOrPasswordReachesAnEventWhateverKeycloakHeard() {
        EventMapper mapper = new EventMapper();
        for (EventType type : EventType.values()) {
            HumifortisEvent out;
            try {
                out = mapper.fromKeycloakEvent(event(type));
            } catch (RuntimeException e) {
                continue; // a type the mapper does not map reports nothing
            }
            if (out == null) continue;
            for (Map.Entry<String, Object> m : out.getMetadata().entrySet()) {
                String key = m.getKey().toLowerCase(Locale.ROOT);
                for (String part : FORBIDDEN_KEY_PARTS) {
                    assertFalse(key.contains(part), type + ": the metadata key " + m.getKey() + " must not exist");
                }
                String value = String.valueOf(m.getValue());
                for (String secret : PLANTED.values()) {
                    assertFalse(value.contains(secret), type + ": the value of " + m.getKey() + " carries a planted secret");
                }
            }
            for (String value : out.getResource() == null ? java.util.List.<String>of() : out.getResource().values()) {
                for (String secret : PLANTED.values()) {
                    assertFalse(value.contains(secret), type + ": a resource value carries a planted secret");
                }
            }
        }
    }

    @Test
    void theAuditLogNamesAPersonByAPseudonym() {
        String uid = "7f3c1a9e-0000-4000-8000-000000000001";
        String pseudo = HumifortisAuditLog.pseudoUser(uid);
        assertTrue(pseudo.startsWith("hf:u:"));
        assertFalse(pseudo.contains(uid), "the Keycloak id is not in the log");
        assertTrue(pseudo.equals(HumifortisAuditLog.pseudoUser(uid)), "stable: the same person is the same pseudonym");
        assertFalse(pseudo.equals(HumifortisAuditLog.pseudoUser("another-user")), "distinct people are distinct pseudonyms");
        assertTrue(HumifortisAuditLog.pseudoUser(null).equals("hf:u:unknown"));
    }
}
