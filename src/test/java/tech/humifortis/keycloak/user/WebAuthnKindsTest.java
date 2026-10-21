package tech.humifortis.keycloak.user;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.keycloak.credential.CredentialModel;

class WebAuthnKindsTest {

    @Test
    void kind_fromTheBackupFlagAndTheTransports() {
        assertEquals("synced", WebAuthnKinds.kind(List.of("internal", "hybrid"), true));
        assertEquals("device_bound", WebAuthnKinds.kind(List.of("internal"), false));
        assertEquals("security_key", WebAuthnKinds.kind(List.of("usb"), false));
        assertEquals("security_key", WebAuthnKinds.kind(List.of("nfc", "usb"), false));
        assertEquals("unknown", WebAuthnKinds.kind(List.of(), false), "no transport: never a guess");
        // no observation of the flag: only a roaming-only credential is told
        assertEquals("security_key", WebAuthnKinds.kind(List.of("USB"), null));
        assertEquals("unknown", WebAuthnKinds.kind(List.of("internal"), null));
        assertEquals("unknown", WebAuthnKinds.kind(null, null));
    }

    @Test
    void rank_ordersTheKinds() {
        assertTrue(WebAuthnKinds.rank("security_key") > WebAuthnKinds.rank("device_bound"));
        assertTrue(WebAuthnKinds.rank("device_bound") > WebAuthnKinds.rank("synced"));
        assertTrue(WebAuthnKinds.rank("synced") > WebAuthnKinds.rank("unknown"));
        assertEquals(0, WebAuthnKinds.rank(null));
    }

    @Test
    void backupEligible_isBit3OfTheFlags() {
        byte[] data = new byte[37];
        data[32] = 0x45; // UP | UV | AT, not BE
        assertFalse(WebAuthnKinds.backupEligible(data));
        data[32] = 0x1D; // UP | UV | BE | BS
        assertTrue(WebAuthnKinds.backupEligible(data));
        assertNull(WebAuthnKinds.backupEligible(new byte[10]), "too short to hold the flags");
    }

    @Test
    void decode_acceptsBase64AndBase64Url() {
        byte[] raw = {(byte) 0xfb, (byte) 0xff, 0x01};
        assertArrayEquals(raw, WebAuthnKinds.decode(Base64.getEncoder().encodeToString(raw)));
        assertArrayEquals(raw, WebAuthnKinds.decode(Base64.getUrlEncoder().withoutPadding().encodeToString(raw)));
        assertNull(WebAuthnKinds.decode("not base64 !"));
    }

    @Test
    void ref_isAStableOpaqueHash() {
        String r = WebAuthnKinds.ref("4f1c-credential-id");
        assertEquals(32, r.length());
        assertEquals(r, WebAuthnKinds.ref("4f1c-credential-id"));
        assertFalse(r.contains("4f1c"));
        assertNull(WebAuthnKinds.ref(""));
    }

    @Test
    void authDataOfAttestation_readsTheCborMap() {
        byte[] authData = new byte[37];
        authData[32] = 0x5D; // UP | UV | BE | BS | AT
        ByteArrayOutputStream cbor = new ByteArrayOutputStream();
        cbor.write(0xA3);                             // map of 3
        text(cbor, "fmt"); text(cbor, "packed");
        text(cbor, "attStmt");
        cbor.write(0xA2);                             // map of 2: alg -7, sig bytes
        text(cbor, "alg"); cbor.write(0x26);          // -7
        text(cbor, "sig"); cbor.write(0x43); cbor.writeBytes(new byte[] {1, 2, 3});
        text(cbor, "authData"); cbor.write(0x58); cbor.write(authData.length); cbor.writeBytes(authData);

        byte[] found = WebAuthnKinds.authDataOfAttestation(cbor.toByteArray());
        assertArrayEquals(authData, found);
        assertTrue(WebAuthnKinds.backupEligible(found));
        assertNull(WebAuthnKinds.authDataOfAttestation(new byte[] {(byte) 0xA3, 0x63}), "truncated: null, never an exception");
        assertNull(WebAuthnKinds.authDataOfAttestation(new byte[] {0x01}), "not a map");
    }

    @Test
    void storedCredentials_areFoundByTheirWebAuthnId_andListedByReference() {
        byte[] id = {9, 8, 7, 6};
        CredentialModel c = new CredentialModel();
        c.setId("kc-cred-1");
        c.setType("webauthn");
        c.setCredentialData("{\"credentialId\":\"" + Base64.getEncoder().encodeToString(id) + "\",\"transports\":[\"usb\",\"nfc\"],\"aaguid\":\"x\"}");
        WebAuthnKinds.Stored s = WebAuthnKinds.parse(c);
        assertEquals(List.of("usb", "nfc"), s.transports());

        // the assertion posts the id base64url-encoded
        assertSame(s, WebAuthnKinds.find(List.of(s), Base64.getUrlEncoder().withoutPadding().encodeToString(id)));
        assertNull(WebAuthnKinds.find(List.of(s), Base64.getUrlEncoder().encodeToString(new byte[] {1})));
        assertEquals(WebAuthnKinds.ref("kc-cred-1") + ":usb+nfc", WebAuthnKinds.held(List.of(s)));
        assertNull(WebAuthnKinds.held(List.of()));

        CredentialModel broken = new CredentialModel();
        broken.setId("kc-cred-2");
        broken.setCredentialData("not json");
        assertEquals(List.of(), WebAuthnKinds.parse(broken).transports(), "unreadable data: no transport, no exception");
    }

    private static void text(ByteArrayOutputStream out, String s) {
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        out.write(0x60 | b.length);
        out.writeBytes(b);
    }
}
