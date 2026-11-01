package tech.humifortis.keycloak.caep;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.UserSessionProvider;
import org.keycloak.models.SubjectCredentialManager;

import com.google.gson.JsonObject;

/** Recovery after a compromise (P25, RC-1..RC-8): which credentials go, what the reply reports, and the realm's opt-in. */
class AccountRecoveryTest {

    private static final Instant INCIDENT = Instant.parse("2026-10-21T12:00:00Z");

    private static CredentialModel cred(String id, String type, Instant created) {
        CredentialModel c = new CredentialModel();
        c.setId(id);
        c.setType(type);
        c.setCreatedDate(created.toEpochMilli());
        return c;
    }

    private static AccountRecovery.Request req(String scope, Instant since, Set<String> refs, boolean codes) {
        return new AccountRecovery.Request(scope, since, refs, true, codes);
    }

    private final CredentialModel oldTotp = cred("c-old-totp", "otp", INCIDENT.minusSeconds(86_400));
    private final CredentialModel newTotp = cred("c-new-totp", "otp", INCIDENT.plusSeconds(60));
    private final CredentialModel newKey = cred("c-new-key", "webauthn", INCIDENT.plusSeconds(120));
    private final CredentialModel oldPasskey = cred("c-old-passkey", "webauthn-passwordless", INCIDENT.minusSeconds(3600));
    private final CredentialModel codes = cred("c-codes", "recovery-authn-codes", INCIDENT.minusSeconds(86_400));
    private final CredentialModel password = cred("c-pass", "password", INCIDENT.minusSeconds(86_400));
    private final List<CredentialModel> all = List.of(oldTotp, newTotp, newKey, oldPasskey, codes, password);

    private static List<String> ids(List<CredentialModel> l) {
        return l.stream().map(CredentialModel::getId).sorted().toList();
    }

    @Test
    void anIncidentRemovesOnlyTheFactorsEnrolledSinceItBegan() {
        List<CredentialModel> out = AccountRecovery.select(all, req("incident", INCIDENT, Set.of(), false));
        assertEquals(List.of("c-new-key", "c-new-totp"), ids(out), "RC-2 / RC-6: what the attacker enrolled, nothing older, never the password");
    }

    @Test
    void everythingRemovesEveryFactorButNeverThePassword() {
        List<CredentialModel> out = AccountRecovery.select(all, req("all", null, Set.of(), false));
        assertEquals(List.of("c-new-key", "c-new-totp", "c-old-passkey", "c-old-totp"), ids(out));
        assertFalse(ids(out).contains("c-pass"));
    }

    @Test
    void theRecoveryCodesGoWhateverTheScopeWhenAsked() {
        List<CredentialModel> out = AccountRecovery.select(all, req("incident", INCIDENT, Set.of(), true));
        assertTrue(ids(out).contains("c-codes"), "RC-5: the old codes no longer work");
        assertEquals(3, out.size());
        assertFalse(ids(AccountRecovery.select(all, req("incident", INCIDENT, Set.of(), false))).contains("c-codes"));
    }

    @Test
    void aLostDeviceRemovesOnlyTheNamedCredentials() {
        String ref = tech.humifortis.keycloak.user.WebAuthnKinds.ref("c-old-passkey");
        List<CredentialModel> out = AccountRecovery.select(all, req("refs", null, Set.of(ref), false));
        assertEquals(List.of("c-old-passkey"), ids(out), "DVL-8");
    }

    @Test
    void anIncidentWithoutATimeRemovesNothing() {
        assertTrue(AccountRecovery.select(all, req("incident", null, Set.of(), false)).isEmpty());
    }

    @Test
    void theRequestNeedsAKnownScope() {
        JsonObject body = new JsonObject();
        body.addProperty("scope", "everything");
        assertNull(AccountRecovery.parse(body));
        assertNull(AccountRecovery.parse(null));
        body.addProperty("scope", "incident");
        body.addProperty("since", 1_700_000_000L);
        body.addProperty("recovery_codes", true);
        AccountRecovery.Request r = AccountRecovery.parse(body);
        assertNotNull(r);
        assertEquals(Instant.ofEpochSecond(1_700_000_000L), r.since());
        assertTrue(r.endSessions(), "sessions end unless the request says otherwise");
        assertTrue(r.recoveryCodes());
    }

    @Test
    void aRemovedFactorMustBeEnrolledAgain() {
        assertEquals("CONFIGURE_TOTP", AccountRecovery.requiredActionFor("otp"));
        assertEquals("webauthn-register", AccountRecovery.requiredActionFor("webauthn"));
        assertEquals("webauthn-register-passwordless", AccountRecovery.requiredActionFor("webauthn-passwordless"));
        assertNull(AccountRecovery.requiredActionFor("recovery-authn-codes"));
    }

    @Test
    void theWebAuthnReferenceIsTheSameAtRemovalAndAtASignInAttempt() {
        byte[] rawId = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
        String b64url = Base64.getUrlEncoder().withoutPadding().encodeToString(rawId);
        CredentialModel c = cred("c-key", "webauthn", INCIDENT);
        c.setCredentialData("{\"credentialId\":\"" + b64url + "\",\"transports\":[\"usb\"]}");
        String atRemoval = AccountRecovery.webauthnRef(c);
        assertNotNull(atRemoval);
        assertEquals(atRemoval, AccountRecovery.idRefOfPosted(b64url), "RC-4 / RC-6: a later attempt with it is recognised");
        assertEquals(atRemoval, AccountRecovery.idRefOfPosted(Base64.getEncoder().encodeToString(rawId)), "base64 or base64url");
        assertEquals(32, atRemoval.length());
        assertNull(AccountRecovery.webauthnRef(cred("c-pass", "password", INCIDENT)));
    }

    @Test
    void theReplyListsWhatWasRemoved() {
        var detail = AccountRecovery.detail(List.of(AccountRecovery.describe(newTotp)), 2, Set.of("CONFIGURE_TOTP"), null);
        assertEquals(2, detail.get("sessions_ended"));
        assertEquals(List.of("CONFIGURE_TOTP"), detail.get("required_actions"));
        assertEquals(1, ((List<?>) detail.get("removed")).size());
    }

    // ── the dispatcher: the realm's opt-in, and what it does to a user ───────────────────────────────────────

    private KeycloakSession session;
    private RealmModel realm;
    private UserModel user;
    private SubjectCredentialManager credentials;
    private UserSessionProvider sessions;
    private UserProvider users;

    @BeforeEach
    void setUp() {
        session = mock(KeycloakSession.class);
        realm = mock(RealmModel.class);
        user = mock(UserModel.class);
        credentials = mock(SubjectCredentialManager.class);
        sessions = mock(UserSessionProvider.class);
        users = mock(UserProvider.class);
        when(session.users()).thenReturn(users);
        when(session.sessions()).thenReturn(sessions);
        when(users.getUserById(realm, "u1")).thenReturn(user);
        when(user.credentialManager()).thenReturn(credentials);
        when(credentials.getStoredCredentialsStream()).thenAnswer(i -> all.stream());
        when(sessions.getUserSessionsStream(realm, user)).thenAnswer(i -> Stream.of(mock(UserSessionModel.class), mock(UserSessionModel.class)));
        when(sessions.getOfflineUserSessionsStream(realm, user)).thenAnswer(i -> Stream.<UserSessionModel>empty());
    }

    private static CaepConfig config(boolean recovery) {
        return new CaepConfig(true, "iss", "aud", "jwks", 60, true, 600, true, true, true, true, false, false, false, recovery);
    }

    private static CaepParsedSet recovery(String subject, JsonObject body) {
        JsonObject events = new JsonObject();
        events.add("https://schemas.humifortis.dev/secevent/event-type/account-recovery", body);
        return new CaepParsedSet("j", "iss", Set.of("aud"), Instant.now(), Instant.now().plusSeconds(60), subject, null, events);
    }

    private static JsonObject body(String scope, long since) {
        JsonObject b = new JsonObject();
        b.addProperty("scope", scope);
        b.addProperty("since", since);
        b.addProperty("end_sessions", true);
        b.addProperty("recovery_codes", true);
        return b;
    }

    @Test
    void withoutTheRealmOptInNothingIsRemoved() {
        CaepDispatchResult r = new CaepActionDispatcher(session).dispatch("account-recovery", recovery("u1", body("all", 0)), config(false), realm);
        assertEquals("ignored", r.processingResult());
        assertTrue(r.error().contains("hf.caep.enforce.accountRecovery"));
        verify(credentials, org.mockito.Mockito.never()).removeStoredCredentialById(any());
    }

    @Test
    void aRecoveryRemovesTheFactorsEndsTheSessionsAndRequiresEnrolment() {
        CaepDispatchResult r = new CaepActionDispatcher(session).dispatch("account-recovery", recovery("u1", body("incident", INCIDENT.getEpochSecond())), config(true), realm);
        assertEquals("processed", r.processingResult());
        assertEquals("account_recovery", r.action());
        verify(credentials).removeStoredCredentialById("c-new-totp");
        verify(credentials).removeStoredCredentialById("c-new-key");
        verify(credentials).removeStoredCredentialById("c-codes");
        verify(credentials, org.mockito.Mockito.never()).removeStoredCredentialById("c-old-totp");
        verify(credentials, org.mockito.Mockito.never()).removeStoredCredentialById("c-pass");
        verify(user).addRequiredAction("CONFIGURE_TOTP");
        verify(user).addRequiredAction("webauthn-register");
        verify(sessions, org.mockito.Mockito.times(2)).removeUserSession(any(), any());
        verify(users).setNotBeforeForUser(any(), any(), anyInt());
        assertEquals(2, r.detail().get("sessions_ended"));
        assertEquals(3, ((List<?>) r.detail().get("removed")).size());
    }

    @Test
    void aMalformedEventDoesNothing() {
        JsonObject bad = new JsonObject();
        bad.addProperty("scope", "nope");
        CaepDispatchResult r = new CaepActionDispatcher(session).dispatch("account-recovery", recovery("u1", bad), config(true), realm);
        assertEquals("ignored", r.processingResult());
        verify(credentials, org.mockito.Mockito.never()).removeStoredCredentialById(any());
    }

    @Test
    void theClientOfAServiceAccountIsRotatedAndDisabledWhenItAllows() {
        ClientModel client = mock(ClientModel.class);
        when(realm.getId()).thenReturn("realm-id");
        when(realm.getClientByClientId("svc")).thenReturn(client);
        when(client.getClientId()).thenReturn("svc");
        when(client.isEnabled()).thenReturn(true);
        when(client.getAttribute("humifortis.allow_disable")).thenReturn("true");
        UserModel serviceUser = mock(UserModel.class);
        when(users.getServiceAccount(client)).thenReturn(serviceUser);
        when(sessions.getUserSessionsStream(realm, serviceUser)).thenAnswer(i -> Stream.of(mock(UserSessionModel.class)));
        when(sessions.getOfflineUserSessionsStream(realm, serviceUser)).thenAnswer(i -> Stream.<UserSessionModel>empty());

        CaepDispatchResult r = new CaepActionDispatcher(session).dispatch("account-recovery",
                recovery("service_account:keycloak:realm-id:svc", body("all", 0)), config(true), realm);
        assertEquals("processed", r.processingResult());
        assertEquals("client_recovered", r.action());
        verify(client, org.mockito.Mockito.atLeastOnce()).setSecret(any());
        verify(client).setEnabled(false);
        assertEquals(1, r.detail().get("sessions_ended"));
    }

    @Test
    void theClientOfAServiceAccountThatDoesNotAllowItIsLeftAlone() {
        ClientModel client = mock(ClientModel.class);
        when(realm.getId()).thenReturn("realm-id");
        when(realm.getClientByClientId("svc")).thenReturn(client);
        CaepDispatchResult r = new CaepActionDispatcher(session).dispatch("account-recovery",
                recovery("service_account:keycloak:realm-id:svc", body("all", 0)), config(true), realm);
        assertEquals("ignored", r.processingResult());
        verify(client, org.mockito.Mockito.never()).setSecret(any());
    }

}
