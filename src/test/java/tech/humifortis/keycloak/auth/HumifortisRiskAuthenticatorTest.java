package tech.humifortis.keycloak.auth;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for HumifortisRiskAuthenticator — UA parsing, device summary.
 * Lives in the auth package to access the package-private static method.
 */
class HumifortisRiskAuthenticatorTest {

    // ── parseDeviceSummary ────────────────────────────────────────────────────

    @Test
    void chrome_windows() {
        String ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  + "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36";
        assertEquals("Chrome on Windows", HumifortisRiskAuthenticator.parseDeviceSummary(ua));
    }

    @Test
    void firefox_linux() {
        String ua = "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0";
        assertEquals("Firefox on Linux", HumifortisRiskAuthenticator.parseDeviceSummary(ua));
    }

    @Test
    void safari_iphone() {
        String ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
                  + "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";
        assertEquals("Safari on iPhone", HumifortisRiskAuthenticator.parseDeviceSummary(ua));
    }

    @Test
    void edge_windows() {
        String ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  + "AppleWebKit/537.36 Chrome/120 Safari/537.36 Edg/120.0";
        assertEquals("Edge on Windows", HumifortisRiskAuthenticator.parseDeviceSummary(ua));
    }

    @Test
    void nullInput_returnsUnknown() {
        assertEquals("Unknown device", HumifortisRiskAuthenticator.parseDeviceSummary(null));
    }

    @Test
    void blankInput_returnsUnknown() {
        assertEquals("Unknown device", HumifortisRiskAuthenticator.parseDeviceSummary("  "));
    }

    @Test
    void safari_ipad() {
        String ua = "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) "
                  + "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/604.1";
        assertEquals("Safari on iPad", HumifortisRiskAuthenticator.parseDeviceSummary(ua));
    }

    @Test
    void chrome_android() {
        String ua = "Mozilla/5.0 (Linux; Android 13; SM-G991B) "
                  + "AppleWebKit/537.36 Chrome/121 Mobile Safari/537.36";
        assertEquals("Chrome on Android", HumifortisRiskAuthenticator.parseDeviceSummary(ua));
    }

    @Test
    void opera_windows() {
        String ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  + "AppleWebKit/537.36 Chrome/120 Safari/537.36 OPR/106";
        assertEquals("Opera on Windows", HumifortisRiskAuthenticator.parseDeviceSummary(ua));
    }

    @Test
    void safari_macos() {
        String ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) "
                  + "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15";
        assertEquals("Safari on macOS", HumifortisRiskAuthenticator.parseDeviceSummary(ua));
    }
}

