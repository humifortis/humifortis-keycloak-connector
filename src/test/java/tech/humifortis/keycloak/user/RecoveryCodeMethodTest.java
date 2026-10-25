package tech.humifortis.keycloak.user;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

class RecoveryCodeMethodTest {

    @Test
    void recoveryCodesAloneAreNoSecondFactor() {
        assertFalse(UserContextExtractor.hasSecondFactor(List.of(UserContextExtractor.RECOVERY_CODE)),
                "codes on paper protect no sign-in by themselves: the account still counts as having no MFA");
        assertFalse(UserContextExtractor.hasSecondFactor(List.of()));
    }

    @Test
    void anAppOrAKeyBesidesThemIsASecondFactor() {
        assertTrue(UserContextExtractor.hasSecondFactor(List.of("TOTP", UserContextExtractor.RECOVERY_CODE)));
        assertTrue(UserContextExtractor.hasSecondFactor(List.of("WEBAUTHN")));
    }
}
