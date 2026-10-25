package tech.humifortis.keycloak.caep;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.keycloak.credential.CredentialModel;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import tech.humifortis.keycloak.user.WebAuthnKinds;

/**
 * Recovery after a compromise (docs/sso-and-external-idp-e2e.spec.md, P25): what the receiver removes from a person.
 *
 * <p>An analyst starts a recovery from an alert; Humifortis sends the Humifortis event {@code account-recovery}. The
 * receiver ends the sessions and tokens, removes the second factors the request selects (authenticator apps and passkeys
 * enrolled since the incident began, or all of them) and the recovery codes, and requires a fresh enrolment at the next
 * sign-in. Selecting is pure and unit-tested here; applying it to a user is {@link CaepActionDispatcher}'s.</p>
 */
public final class AccountRecovery {

    public static final String SCOPE_INCIDENT = "incident";
    public static final String SCOPE_ALL = "all";
    public static final String SCOPE_REFS = "refs";

    static final Set<String> FACTOR_TYPES = Set.of("otp", "webauthn", "webauthn-passwordless");
    static final String RECOVERY_CODES_TYPE = "recovery-authn-codes";

    /** What the request asks for. */
    public record Request(String scope, Instant since, Set<String> refs, boolean endSessions, boolean recoveryCodes) {}

    /** A credential taken away, as reported back to Humifortis. */
    public record Removed(String type, String ref, String webauthnRef, Long createdAt) {}

    private AccountRecovery() {}

    /** Reads the body of the event; null when it names no known scope. */
    public static Request parse(JsonObject body) {
        if (body == null) return null;
        String scope = str(body, "scope");
        if (!SCOPE_INCIDENT.equals(scope) && !SCOPE_ALL.equals(scope) && !SCOPE_REFS.equals(scope)) return null;
        Instant since = body.has("since") && body.get("since").isJsonPrimitive() ? Instant.ofEpochSecond(body.get("since").getAsLong()) : null;
        Set<String> refs = new LinkedHashSet<>();
        if (body.has("refs") && body.get("refs").isJsonArray()) {
            for (JsonElement e : body.getAsJsonArray("refs")) refs.add(e.getAsString());
        }
        boolean end = !body.has("end_sessions") || body.get("end_sessions").getAsBoolean();
        boolean codes = body.has("recovery_codes") && body.get("recovery_codes").getAsBoolean();
        return new Request(scope, since, refs, end, codes);
    }

    private static String str(JsonObject o, String k) {
        return o.has(k) && o.get(k).isJsonPrimitive() ? o.get(k).getAsString() : null;
    }

    /**
     * The credentials the request removes. Recovery codes go whenever the request says so, whatever the scope (the old codes
     * must not work, RC-5); a second factor goes when the scope is "all", when it was created at or after the incident began
     * ("incident"), or when its reference is named ("refs"). A password is never touched.
     */
    public static List<CredentialModel> select(List<CredentialModel> stored, Request req) {
        List<CredentialModel> out = new ArrayList<>();
        for (CredentialModel c : stored) {
            if (c.getType() == null) continue;
            if (RECOVERY_CODES_TYPE.equals(c.getType())) {
                if (req.recoveryCodes()) out.add(c);
                continue;
            }
            if (!FACTOR_TYPES.contains(c.getType())) continue;
            boolean take = switch (req.scope()) {
                case SCOPE_ALL -> true;
                case SCOPE_INCIDENT -> req.since() != null && c.getCreatedDate() != null && c.getCreatedDate() >= req.since().toEpochMilli();
                case SCOPE_REFS -> req.refs().contains(WebAuthnKinds.ref(c.getId()));
                default -> false;
            };
            if (take) out.add(c);
        }
        return out;
    }

    /** The required action that makes the person enrol again after a factor of this type was removed (null: none). */
    public static String requiredActionFor(String credentialType) {
        if (credentialType == null) return null;
        return switch (credentialType) {
            case "otp" -> "CONFIGURE_TOTP";
            case "webauthn" -> "webauthn-register";
            case "webauthn-passwordless" -> "webauthn-register-passwordless";
            default -> null;
        };
    }

    /** The hash of the WebAuthn credential id (the bytes the browser presents), 32 hex digits; null when unreadable. */
    public static String webauthnRef(CredentialModel c) {
        if (c == null || c.getCredentialData() == null) return null;
        try {
            JsonObject data = JsonParser.parseString(c.getCredentialData()).getAsJsonObject();
            if (!data.has("credentialId") || data.get("credentialId").isJsonNull()) return null;
            return idRef(WebAuthnKinds.decode(data.get("credentialId").getAsString()));
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** The same hash, from the id as a browser posts it (base64 or base64url). */
    public static String idRefOfPosted(String credentialIdB64) {
        return idRef(WebAuthnKinds.decode(credentialIdB64));
    }

    static String idRef(byte[] id) {
        if (id == null || id.length == 0) return null;
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(id)).substring(0, 32);
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    public static Removed describe(CredentialModel c) {
        return new Removed(c.getType(), WebAuthnKinds.ref(c.getId()), webauthnRef(c), c.getCreatedDate());
    }

    /** The detail of the reply: what was removed, how many sessions ended, what the next sign-in must do. */
    public static Map<String, Object> detail(List<Removed> removed, int sessionsEnded, Set<String> requiredActions, String client) {
        Map<String, Object> d = new LinkedHashMap<>();
        List<Map<String, Object>> list = new ArrayList<>();
        for (Removed r : removed) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("type", r.type());
            m.put("ref", r.ref());
            if (r.webauthnRef() != null) m.put("webauthn_ref", r.webauthnRef());
            if (r.createdAt() != null) m.put("created_at", Instant.ofEpochMilli(r.createdAt()).toString());
            list.add(m);
        }
        d.put("removed", list);
        d.put("sessions_ended", sessionsEnded);
        d.put("required_actions", new ArrayList<>(requiredActions));
        if (client != null) d.put("client", client);
        return d;
    }

    /** True for the subject of a service account (its client is rotated and disabled instead). */
    static boolean isServiceAccount(String subject) {
        return subject != null && subject.startsWith(CaepActionDispatcher.SERVICE_ACCOUNT_SUBJECT);
    }

    static final String SMS_ATTRIBUTE_ENV = "HUMIFORTIS_SMS_PHONE_ATTRIBUTE";
    static final String SMS_ATTRIBUTE_DEFAULT = "phoneNumber";

    /** The attribute that holds the person's text-message number. */
    static String smsAttribute(Map<String, String> env) {
        String v = env.get(SMS_ATTRIBUTE_ENV);
        return v == null || v.isBlank() ? SMS_ATTRIBUTE_DEFAULT : v.trim();
    }

}
