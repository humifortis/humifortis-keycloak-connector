package tech.humifortis.keycloak.token;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

class RiskEpochTest {

    @Test
    void aNoteIsReadAsAPositiveNumber() {
        assertEquals(3L, RiskEpoch.parse("3"));
        assertEquals(12L, RiskEpoch.parse(" 12 "));
    }

    @Test
    void noNoteAGarbledNoteOrZeroIsNoEpoch() {
        assertNull(RiskEpoch.parse(null));
        assertNull(RiskEpoch.parse(""));
        assertNull(RiskEpoch.parse("x"));
        assertNull(RiskEpoch.parse("0"));
        assertNull(RiskEpoch.parse("-2"));
    }

    @Test
    void aMissingSessionIsHarmless() {
        assertNull(RiskEpoch.of(null));
        RiskEpoch.record(null, 4);
    }
}
