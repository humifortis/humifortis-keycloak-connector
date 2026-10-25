package tech.humifortis.keycloak.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class TrustCookieTest {

    @Test
    void noPrefixKeepsTheRealmPath() {
        assertEquals("/realms/demo", TrustCookie.path("/", "demo"));
        assertEquals("/realms/demo", TrustCookie.path("", "demo"));
        assertEquals("/realms/demo", TrustCookie.path(null, "demo"));
    }

    @Test
    void aPrefixOfTheFrontendUrlIsPartOfThePath() {
        assertEquals("/auth/realms/demo", TrustCookie.path("/auth/", "demo"));
        assertEquals("/auth/realms/demo", TrustCookie.path("/auth", "demo"));
        assertEquals("/sso/auth/realms/demo", TrustCookie.path("sso/auth//", "demo"));
    }
}
