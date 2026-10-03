package tech.humifortis.keycloak.auth;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.sessions.AuthenticationSessionModel;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/** The two ways device signals reach the collector step — and that neither ever blocks a login. */
class HumifortisDeviceCollectorAuthenticatorTest {

    private final HumifortisDeviceCollectorAuthenticator collector = new HumifortisDeviceCollectorAuthenticator();

    private static AuthenticationFlowContext context(String method, MultivaluedMap<String, String> form, AuthenticationSessionModel session) {
        AuthenticationFlowContext ctx = mock(AuthenticationFlowContext.class);
        HttpRequest request = mock(HttpRequest.class);
        when(request.getHttpMethod()).thenReturn(method);
        when(request.getDecodedFormParameters()).thenReturn(form);
        when(ctx.getHttpRequest()).thenReturn(request);
        when(ctx.getAuthenticationSession()).thenReturn(session);
        return ctx;
    }

    private static MultivaluedMap<String, String> loginPost(String tabId) {
        long ts = System.currentTimeMillis();
        MultivaluedMap<String, String> f = new MultivaluedHashMap<>();
        f.add("username", "alice");
        f.add("password", "secret");
        f.add("device_id", "dev-1");
        f.add("device_tz", "America/Halifax");
        f.add("device_timestamp", String.valueOf(ts));
        f.add("device_binding", DeviceSignals.sha256Hex(tabId + ":" + ts + ":dev-1"));
        return f;
    }

    @Test
    void signalsFromTheLoginPage_noExtraPage_bindingCheckedAgainstTheTabId() {
        AuthenticationSessionModel session = mock(AuthenticationSessionModel.class);
        when(session.getTabId()).thenReturn("tab-9");
        AuthenticationFlowContext ctx = context("POST", loginPost("tab-9"), session);

        collector.authenticate(ctx);

        verify(ctx).success();
        verify(ctx, never()).forceChallenge(any());
        verify(session).setAuthNote(HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_ID, "dev-1");
        verify(session).setAuthNote(HumifortisDeviceCollectorAuthenticator.NOTE_BINDING_RESULT, DeviceSignals.VALID);
    }

    @Test
    void noSignalsOnTheLoginPost_rendersTheCollectorPageWithANonce() {
        AuthenticationSessionModel session = mock(AuthenticationSessionModel.class);
        MultivaluedMap<String, String> plain = new MultivaluedHashMap<>();
        plain.add("username", "alice");
        AuthenticationFlowContext ctx = context("POST", plain, session);
        LoginFormsProvider forms = mock(LoginFormsProvider.class);
        when(ctx.form()).thenReturn(forms);
        when(forms.setAttribute(anyString(), any())).thenReturn(forms);
        when(forms.createForm(anyString())).thenReturn(Response.ok().build());

        collector.authenticate(ctx);

        verify(ctx).forceChallenge(any());
        verify(ctx, never()).success();
        verify(forms).setAttribute(eq("deviceNonce"), anyString());
        verify(session).setAuthNote(eq("HUMIFORTIS_DEVICE_NONCE"), anyString());
    }

    @Test
    void collectorPageSubmission_validatedAgainstTheRenderedNonce() {
        AuthenticationSessionModel session = mock(AuthenticationSessionModel.class);
        when(session.getAuthNote("HUMIFORTIS_DEVICE_NONCE")).thenReturn("nonce-1");
        AuthenticationFlowContext ctx = context("POST", loginPost("nonce-1"), session);

        collector.action(ctx);

        verify(ctx).success();
        verify(session).setAuthNote(HumifortisDeviceCollectorAuthenticator.NOTE_BINDING_RESULT, DeviceSignals.VALID);
    }

    @Test
    void javascriptDisabled_emptySubmission_continuesFailOpen() {
        AuthenticationSessionModel session = mock(AuthenticationSessionModel.class);
        AuthenticationFlowContext ctx = context("POST", new MultivaluedHashMap<>(), session);

        collector.action(ctx);

        verify(ctx).success();
        verify(session).setAuthNote(HumifortisDeviceCollectorAuthenticator.NOTE_BINDING_RESULT, DeviceSignals.ABSENT);
    }

    @Test
    void unreadableRequest_continuesFailOpen() {
        AuthenticationSessionModel session = mock(AuthenticationSessionModel.class);
        AuthenticationFlowContext ctx = mock(AuthenticationFlowContext.class);
        when(ctx.getHttpRequest()).thenThrow(new IllegalStateException("no request"));
        when(ctx.getAuthenticationSession()).thenReturn(session);

        collector.action(ctx);

        verify(ctx).success();
    }
}
