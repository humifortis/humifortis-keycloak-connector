package tech.humifortis.keycloak.external;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.Test;
import org.keycloak.models.UserModel;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

class ExternalSignalsTest {

    private static final String PHONE = "+15145550100";

    /** A transport that answers by URL and counts the questions. */
    private static final class Fake implements ExternalSignals.Transport {
        final Map<String, String> answers;
        final List<Map<String, Object>> asked = new ArrayList<>();
        boolean down;

        Fake(Map<String, String> answers) {
            this.answers = answers;
        }

        @Override
        public JsonObject post(String url, String token, Map<String, Object> body) throws Exception {
            asked.add(body);
            if (down) throw new java.io.IOException("unreachable");
            return JsonParser.parseString(answers.get(url)).getAsJsonObject();
        }
    }

    private static ExternalSignals signals(Map<String, String> env, Fake fake, AtomicLong clock) {
        return new ExternalSignals(env, fake, clock::get);
    }

    @Test
    void withoutItsSettingASignalDoesNotExist_nothingIsAsked() {
        Fake fake = new Fake(Map.of());
        ExternalSignals s = signals(Map.of(), fake, new AtomicLong());
        assertNull(s.simSwappedRecently(PHONE));
        assertNull(s.numberVerified(PHONE));
        assertNull(s.devicePosture("dev-1"));
        assertTrue(fake.asked.isEmpty());
    }

    @Test
    void anInsecureUrlIsNotUsedUnlessAllowed() {
        Fake fake = new Fake(Map.of("http://camara.local/swap", "{\"swapped\":true}"));
        assertNull(signals(Map.of(ExternalSignals.ENV_SIM_SWAP, "http://camara.local/swap"), fake, new AtomicLong()).simSwappedRecently(PHONE));
        assertEquals(Boolean.TRUE, signals(Map.of(ExternalSignals.ENV_SIM_SWAP, "http://camara.local/swap", "HUMIFORTIS_ALLOW_INSECURE_HTTP", "true"),
                fake, new AtomicLong()).simSwappedRecently(PHONE));
    }

    @Test
    void aSimSwapIsReadAndAskedWithTheConfiguredAge() {
        Fake fake = new Fake(Map.of("https://camara/swap", "{\"swapped\":true}"));
        ExternalSignals s = signals(Map.of(ExternalSignals.ENV_SIM_SWAP, "https://camara/swap", "HUMIFORTIS_SIM_SWAP_MAX_AGE_HOURS", "48"), fake, new AtomicLong());
        assertEquals(Boolean.TRUE, s.simSwappedRecently(PHONE));
        assertEquals(48, fake.asked.get(0).get("maxAge"));
        assertEquals(PHONE, fake.asked.get(0).get("phoneNumber"));
    }

    @Test
    void anAnswerIsKeptFiveMinutes_thenAskedAgain() {
        Fake fake = new Fake(Map.of("https://camara/swap", "{\"swapped\":false}"));
        AtomicLong clock = new AtomicLong(1_000);
        ExternalSignals s = signals(Map.of(ExternalSignals.ENV_SIM_SWAP, "https://camara/swap"), fake, clock);
        s.simSwappedRecently(PHONE);
        clock.addAndGet(299_000);
        s.simSwappedRecently(PHONE);
        assertEquals(1, fake.asked.size());
        clock.addAndGet(2_000);
        s.simSwappedRecently(PHONE);
        assertEquals(2, fake.asked.size());
    }

    @Test
    void aSignalThatDoesNotAnswerIsAbsent_failOpen_andNotCached() {
        Fake fake = new Fake(Map.of("https://camara/swap", "{\"swapped\":true}"));
        fake.down = true;
        ExternalSignals s = signals(Map.of(ExternalSignals.ENV_SIM_SWAP, "https://camara/swap"), fake, new AtomicLong());
        assertNull(s.simSwappedRecently(PHONE));
        fake.down = false;
        assertEquals(Boolean.TRUE, s.simSwappedRecently(PHONE), "the failure was not remembered");
    }

    @Test
    void aMalformedAnswerIsNotASignal() {
        Fake fake = new Fake(Map.of("https://camara/swap", "{\"swapped\":\"maybe\"}", "https://mdm/p", "{\"status\":\"weird\"}"));
        assertNull(signals(Map.of(ExternalSignals.ENV_SIM_SWAP, "https://camara/swap"), fake, new AtomicLong()).simSwappedRecently(PHONE));
        assertNull(signals(Map.of(ExternalSignals.ENV_DEVICE_POSTURE, "https://mdm/p"), fake, new AtomicLong()).devicePosture("d"));
    }

    @Test
    void theDevicePostureIsOneOfThreeValues() {
        for (String status : new String[] {"compliant", "non_compliant", "unknown"}) {
            Fake fake = new Fake(Map.of("https://mdm/p", "{\"status\":\"" + status.toUpperCase() + "\"}"));
            assertEquals(status, signals(Map.of(ExternalSignals.ENV_DEVICE_POSTURE, "https://mdm/p"), fake, new AtomicLong()).devicePosture("dev-1"));
        }
        Fake dash = new Fake(Map.of("https://mdm/p", "{\"status\":\"non-compliant\"}"));
        assertEquals("non_compliant", signals(Map.of(ExternalSignals.ENV_DEVICE_POSTURE, "https://mdm/p"), dash, new AtomicLong()).devicePosture("dev-1"));
    }

    @Test
    void aNumberThatChangedHandsIsNotTexted() {
        Fake fake = new Fake(Map.of("https://camara/swap", "{\"swapped\":true}"));
        ExternalSignals s = signals(Map.of(ExternalSignals.ENV_SIM_SWAP, "https://camara/swap"), fake, new AtomicLong());
        assertFalse(s.mayText(mock(UserModel.class), PHONE));
    }

    @Test
    void anUnverifiedNumberIsVerifiedBeforeTheFirstText_andRemembered() {
        Fake fake = new Fake(Map.of("https://camara/verify", "{\"devicePhoneNumberVerified\":true}"));
        ExternalSignals s = signals(Map.of(ExternalSignals.ENV_NUMBER_VERIFICATION, "https://camara/verify"), fake, new AtomicLong());
        UserModel user = mock(UserModel.class);
        when(user.getFirstAttribute(ExternalSignals.ATTR_VERIFIED_NUMBER)).thenReturn(null);
        assertTrue(s.mayText(user, PHONE));
        verify(user).setSingleAttribute(ExternalSignals.ATTR_VERIFIED_NUMBER, PHONE);

        UserModel known = mock(UserModel.class);
        when(known.getFirstAttribute(ExternalSignals.ATTR_VERIFIED_NUMBER)).thenReturn(PHONE);
        int before = fake.asked.size();
        assertTrue(s.mayText(known, PHONE));
        assertEquals(before, fake.asked.size(), "a verified number is not verified again");
    }

    @Test
    void aNumberThatIsNotTheDevicesIsNotTexted() {
        Fake fake = new Fake(Map.of("https://camara/verify", "{\"devicePhoneNumberVerified\":false}"));
        ExternalSignals s = signals(Map.of(ExternalSignals.ENV_NUMBER_VERIFICATION, "https://camara/verify"), fake, new AtomicLong());
        assertFalse(s.mayText(mock(UserModel.class), PHONE));
    }

    @Test
    void verificationThatDoesNotAnswerLetsTheTextGo() {
        Fake fake = new Fake(Map.of());
        fake.down = true;
        ExternalSignals s = signals(Map.of(ExternalSignals.ENV_NUMBER_VERIFICATION, "https://camara/verify"), fake, new AtomicLong());
        assertTrue(s.mayText(mock(UserModel.class), PHONE));
    }

    @Test
    void withNoSettingTheTextGoes() {
        assertTrue(signals(Map.of(), new Fake(Map.of()), new AtomicLong()).mayText(mock(UserModel.class), PHONE));
    }
}
