package tech.humifortis.keycloak.auth;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import org.junit.jupiter.api.Test;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class DeviceSignalsTest {

    private static final String NONCE = "tab-123";
    private static final long NOW = 1_800_000_000_000L;

    /** A login/collector POST as the bundle writes it, bound to NONCE at {@code ts}. */
    private static MultivaluedMap<String, String> form(long ts) {
        MultivaluedMap<String, String> f = new MultivaluedHashMap<>();
        f.add("username", "alice");
        f.add("password", "secret");
        f.add("device_id", "459ee90e273ce84d488f8d287d990a59");
        f.add("device_tz", "America/Halifax");
        f.add("device_screen", "1363x941");
        f.add("device_signals", "{\"canvas\":\"x\"}");
        f.add("device_timestamp", String.valueOf(ts));
        f.add("device_binding", DeviceSignals.sha256Hex(NONCE + ":" + ts + ":459ee90e273ce84d488f8d287d990a59"));
        return f;
    }

    @Test
    void noDeviceIdMeansTheScriptDidNotRun() {
        MultivaluedMap<String, String> f = new MultivaluedHashMap<>();
        f.add("username", "alice");
        f.add("device_tz", "America/Halifax");
        assertNull(DeviceSignals.fromForm(f));
        assertNull(DeviceSignals.fromForm(null));
    }

    @Test
    void readsOnlyTheDeviceFields() {
        DeviceSignals s = DeviceSignals.fromForm(form(NOW));
        assertNotNull(s);
        assertEquals("459ee90e273ce84d488f8d287d990a59", s.deviceId());
        assertEquals("America/Halifax", s.get("device_tz"));
        assertNull(s.get("password"), "never anything but device_* fields");
    }

    @Test
    void bindingVerdicts() {
        assertEquals(DeviceSignals.VALID, DeviceSignals.fromForm(form(NOW)).validateBinding(NONCE, NOW + 1_000));
        assertEquals(DeviceSignals.STALE, DeviceSignals.fromForm(form(NOW)).validateBinding(NONCE, NOW + 31_000));
        assertEquals(DeviceSignals.MISMATCH, DeviceSignals.fromForm(form(NOW)).validateBinding("another-tab", NOW));

        MultivaluedMap<String, String> tampered = form(NOW);
        tampered.putSingle("device_id", "ffffffffffffffffffffffffffffffff");
        assertEquals(DeviceSignals.MISMATCH, DeviceSignals.fromForm(tampered).validateBinding(NONCE, NOW), "device_id changed after binding");

        MultivaluedMap<String, String> unbound = form(NOW);
        unbound.remove("device_binding");
        assertEquals(DeviceSignals.ABSENT, DeviceSignals.fromForm(unbound).validateBinding(NONCE, NOW));

        assertEquals(DeviceSignals.ERROR, DeviceSignals.fromForm(form(NOW)).validateBinding(null, NOW), "no nonce on the server side");
        MultivaluedMap<String, String> badTs = form(NOW);
        badTs.putSingle("device_timestamp", "not-a-number");
        assertEquals(DeviceSignals.ERROR, DeviceSignals.fromForm(badTs).validateBinding(NONCE, NOW));
    }

    @Test
    void eventDetailsCarryTheSignalsAndTheVerdictNeverTheBindingMaterial() {
        Map<String, String> details = new LinkedHashMap<>();
        DeviceSignals.fromForm(form(NOW)).writeEventDetails(details::put, DeviceSignals.VALID, true);
        assertEquals("459ee90e273ce84d488f8d287d990a59", details.get("device_id"));
        assertEquals("valid", details.get("device_binding_result"));
        assertTrue(details.containsKey("device_signals"));
        assertFalse(details.containsKey("device_binding"));
        assertFalse(details.containsKey("device_timestamp"));

        Map<String, String> lean = new LinkedHashMap<>();
        DeviceSignals.fromForm(form(NOW)).writeEventDetails(lean::put, DeviceSignals.VALID, false);
        assertFalse(lean.containsKey("device_signals"), "the raw component map can be left out");
    }

    @Test
    void notesAreTheOnesTheRiskEvaluatorReads() {
        AuthenticationSessionModel session = mock(AuthenticationSessionModel.class);
        DeviceSignals.fromForm(form(NOW)).storeAsNotes(session, DeviceSignals.VALID);
        verify(session).setAuthNote(HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_ID, "459ee90e273ce84d488f8d287d990a59");
        verify(session).setAuthNote(HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_TZ, "America/Halifax");
        verify(session).setAuthNote(HumifortisDeviceCollectorAuthenticator.NOTE_BINDING_RESULT, "valid");
    }

    @Test
    void forwardedFieldsAreEveryFieldButTheBindingMaterialAndRawMap() {
        for (String field : DeviceSignals.FIELDS.keySet()) {
            boolean expected = !field.equals("device_binding") && !field.equals("device_timestamp") && !field.equals("device_signals");
            assertEquals(expected, DeviceSignals.EVENT_FIELDS.contains(field), field);
        }
        assertTrue(DeviceSignals.EVENT_FIELDS.contains("device_binding_result"));
    }
}
