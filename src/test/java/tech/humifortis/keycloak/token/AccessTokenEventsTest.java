package tech.humifortis.keycloak.token;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

class AccessTokenEventsTest {

    @Test
    void theTokenIsTheSecondWordOfABearerOrDpopHeader() {
        assertEquals("abc.def.ghi", AccessTokenEvents.tokenOf("DPoP abc.def.ghi"));
        assertEquals("abc.def.ghi", AccessTokenEvents.tokenOf("bearer abc.def.ghi"));
    }

    @Test
    void anythingElseGivesNoToken() {
        assertNull(AccessTokenEvents.tokenOf(null));
        assertNull(AccessTokenEvents.tokenOf("Basic dXNlcjpwYXNz"));
        assertNull(AccessTokenEvents.tokenOf("Bearer"));
        assertNull(AccessTokenEvents.tokenOf("Bearer   "));
    }
}
