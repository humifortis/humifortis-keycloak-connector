package tech.humifortis.keycloak.user;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

import org.keycloak.credential.CredentialModel;
import org.keycloak.models.UserModel;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * The kind of a WebAuthn credential (docs/sso-and-external-idp-e2e.spec.md, P9): a security key, a device-bound passkey
 * or a synced passkey. The factor stays WEBAUTHN; the kind says where the private key lives.
 *
 * <p>Keycloak 26 keeps a credential's transports but not its backup flags (spike S9). The backup-eligible flag is in the
 * authenticator data the browser posts, at the registration (inside the attestation object) and at every use (the
 * assertion): the connector reads it there. A credential is named by a reference: a hash of Keycloak's own credential id,
 * the same at registration, at use and in the list of the credentials a person holds; never the WebAuthn id itself.</p>
 */
public final class WebAuthnKinds {

    public static final String SECURITY_KEY = "security_key";
    public static final String DEVICE_BOUND = "device_bound";
    public static final String SYNCED = "synced";
    public static final String UNKNOWN = "unknown";

    private static final Set<String> ROAMING = Set.of("usb", "nfc", "ble");
    private static final Set<String> WEBAUTHN_TYPES = Set.of("webauthn", "webauthn-passwordless");
    /** Flags byte of the authenticator data (after the 32-byte RP id hash); BE is bit 3. */
    private static final int FLAGS_OFFSET = 32;
    private static final int FLAG_BACKUP_ELIGIBLE = 0x08;
    /** Bound on the credentials listed per person. */
    static final int MAX_CREDENTIALS = 20;

    private WebAuthnKinds() {}

    /**
     * The kind from the transports and the backup-eligible flag. Backup eligible: synced. Not backup eligible: a platform
     * transport is a device-bound passkey, a roaming one a security key. Flag unknown (no observation): only a
     * roaming-only credential is told (a security key); anything else is unknown, never a guess.
     */
    public static String kind(Collection<String> transports, Boolean backupEligible) {
        Set<String> t = transports == null ? Set.of()
                : transports.stream().filter(s -> s != null && !s.isBlank()).map(s -> s.trim().toLowerCase(Locale.ROOT)).collect(Collectors.toSet());
        if (Boolean.TRUE.equals(backupEligible)) return SYNCED;
        if (backupEligible == null) return !t.isEmpty() && ROAMING.containsAll(t) ? SECURITY_KEY : UNKNOWN;
        if (t.contains("internal")) return DEVICE_BOUND;
        if (t.stream().anyMatch(ROAMING::contains)) return SECURITY_KEY;
        return UNKNOWN;
    }

    /** Orders the kinds from the weakest (unknown) to the strongest (security key). */
    public static int rank(String kind) {
        if (kind == null) return 0;
        return switch (kind) {
            case SECURITY_KEY -> 3;
            case DEVICE_BOUND -> 2;
            case SYNCED -> 1;
            default -> 0;
        };
    }

    /** The backup-eligible flag of authenticator data, or null when it is too short to hold the flags. */
    public static Boolean backupEligible(byte[] authenticatorData) {
        if (authenticatorData == null || authenticatorData.length <= FLAGS_OFFSET) return null;
        return (authenticatorData[FLAGS_OFFSET] & FLAG_BACKUP_ELIGIBLE) != 0;
    }

    /** Base64 or base64url, padded or not; null when it is not base64. */
    public static byte[] decode(String b64) {
        if (b64 == null || b64.isBlank()) return null;
        String s = b64.trim().replace('-', '+').replace('_', '/');
        while (s.length() % 4 != 0) s += "=";
        try {
            return Base64.getDecoder().decode(s);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** The reference of a Keycloak credential: the first 32 hex digits of the SHA-256 of its id. */
    public static String ref(String keycloakCredentialId) {
        if (keycloakCredentialId == null || keycloakCredentialId.isBlank()) return null;
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(keycloakCredentialId.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(h).substring(0, 32);
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    /** A WebAuthn credential Keycloak stores for the person, with its WebAuthn id and its transports. */
    public record Stored(String keycloakId, byte[] webauthnId, List<String> transports) {
        public String ref() {
            return WebAuthnKinds.ref(keycloakId);
        }
    }

    /** The person's WebAuthn credentials, as Keycloak stores them (bounded). Never throws. */
    public static List<Stored> stored(UserModel user) {
        List<Stored> out = new ArrayList<>();
        try {
            user.credentialManager().getStoredCredentialsStream()
                    .filter(c -> WEBAUTHN_TYPES.contains(c.getType()))
                    .limit(MAX_CREDENTIALS)
                    .forEach(c -> out.add(parse(c)));
        } catch (RuntimeException e) {
            // unreadable: no credential listed
        }
        return out;
    }

    static Stored parse(CredentialModel c) {
        byte[] id = null;
        List<String> transports = new ArrayList<>();
        try {
            JsonObject data = JsonParser.parseString(c.getCredentialData()).getAsJsonObject();
            if (data.has("credentialId") && !data.get("credentialId").isJsonNull()) id = decode(data.get("credentialId").getAsString());
            if (data.has("transports") && data.get("transports").isJsonArray()) {
                for (JsonElement t : data.getAsJsonArray("transports")) transports.add(t.getAsString());
            }
        } catch (RuntimeException e) {
            // no readable data: no id, no transports
        }
        return new Stored(c.getId(), id, transports);
    }

    /** The stored credential whose WebAuthn id is this one (base64 or base64url), or null. */
    public static Stored find(List<Stored> stored, String webauthnIdB64) {
        byte[] id = decode(webauthnIdB64);
        if (id == null) return null;
        for (Stored s : stored) {
            if (s.webauthnId() != null && MessageDigest.isEqual(s.webauthnId(), id)) return s;
        }
        return null;
    }

    /** The held credentials as the connector reports them: {@code <ref>:<transport>+<transport>,...}; null when none. */
    public static String held(List<Stored> stored) {
        String joined = stored.stream()
                .filter(s -> s.ref() != null)
                .map(s -> s.ref() + ":" + String.join("+", s.transports()))
                .collect(Collectors.joining(","));
        return joined.isEmpty() ? null : joined;
    }

    /**
     * The authenticator data inside a WebAuthn attestation object (CBOR map {fmt, attStmt, authData}), or null. A minimal
     * reader: definite lengths only (an attestation object is canonical CBOR), every other item skipped.
     */
    public static byte[] authDataOfAttestation(byte[] attestationObject) {
        if (attestationObject == null) return null;
        try {
            Cbor c = new Cbor(attestationObject);
            c.head();
            if (c.major != 5) return null;
            long entries = c.arg;
            for (long i = 0; i < entries; i++) {
                c.head();
                String key = c.major == 3 ? c.text() : null;
                if (key == null) {
                    c.skipBody();
                    c.skip();
                    continue;
                }
                if ("authData".equals(key)) {
                    c.head();
                    return c.major == 2 ? c.bytes() : null;
                }
                c.skip();
            }
        } catch (RuntimeException e) {
            return null;
        }
        return null;
    }

    private static final class Cbor {
        private final byte[] b;
        private int p;
        int major;
        long arg;

        Cbor(byte[] b) {
            this.b = b;
        }

        void head() {
            int ib = b[p++] & 0xff;
            major = ib >>> 5;
            int ai = ib & 0x1f;
            if (ai < 24) arg = ai;
            else if (ai == 24) arg = b[p++] & 0xff;
            else if (ai == 25) arg = ((b[p++] & 0xffL) << 8) | (b[p++] & 0xffL);
            else if (ai == 26) arg = ((b[p++] & 0xffL) << 24) | ((b[p++] & 0xffL) << 16) | ((b[p++] & 0xffL) << 8) | (b[p++] & 0xffL);
            else if (ai == 27) {
                arg = 0;
                for (int i = 0; i < 8; i++) arg = (arg << 8) | (b[p++] & 0xffL);
            } else throw new IllegalStateException("unsupported CBOR length");
        }

        String text() {
            String s = new String(b, p, Math.toIntExact(arg), StandardCharsets.UTF_8);
            p += (int) arg;
            return s;
        }

        byte[] bytes() {
            byte[] out = java.util.Arrays.copyOfRange(b, p, Math.addExact(p, Math.toIntExact(arg)));
            p += (int) arg;
            return out;
        }

        /** Skips the body of the item whose head was just read. */
        void skipBody() {
            long n = arg; // the nested heads overwrite arg
            switch (major) {
                case 2, 3 -> p = Math.addExact(p, Math.toIntExact(n));
                case 4 -> { for (long i = 0; i < n; i++) skip(); }
                case 5 -> { for (long i = 0; i < 2 * n; i++) skip(); }
                case 6 -> skip();
                default -> { } // integers, simple values, floats: the head held them
            }
            if (p > b.length) throw new IllegalStateException("truncated CBOR");
        }

        /** Skips one whole item. */
        void skip() {
            head();
            skipBody();
        }
    }
}
