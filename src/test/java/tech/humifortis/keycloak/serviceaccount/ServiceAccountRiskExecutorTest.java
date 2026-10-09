package tech.humifortis.keycloak.serviceaccount;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import jakarta.ws.rs.core.MultivaluedHashMap;

import org.junit.jupiter.api.Test;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.context.ServiceAccountTokenRequestContext;

import tech.humifortis.keycloak.auth.DecisionReport;
import tech.humifortis.keycloak.auth.HumifortisRiskEvaluator;

class ServiceAccountRiskExecutorTest {

    private static HumifortisRiskEvaluator.ServiceAccountResult answer(String action, String enforced, String mode, boolean advisory) {
        HumifortisRiskEvaluator.EvaluateResponse r = new HumifortisRiskEvaluator.EvaluateResponse();
        r.action = action;
        r.enforced_action = enforced;
        r.mode = mode;
        r.advisory = advisory;
        r.playbook_rule = "sa_rule";
        r.risk_level = "CRITICAL";
        return new HumifortisRiskEvaluator.ServiceAccountResult(r, null);
    }

    private static HumifortisRiskEvaluator.ServiceAccountResult noAnswer(String reason) {
        return new HumifortisRiskEvaluator.ServiceAccountResult(null, reason);
    }

    @Test
    void onlyAnEnforcedDenyInEnforceModeRefusesTheRequest() {
        ServiceAccountRiskExecutor.Decision d = ServiceAccountRiskExecutor.decide(answer("DENY", "DENY", "enforce", false), null, false);
        assertTrue(d.refuse());
        assertEquals(DecisionReport.DECISION_ENFORCED, d.reportType());

        assertFalse(ServiceAccountRiskExecutor.decide(answer("DENY", "DENY", "shadow", false), null, false).refuse(), "shadow lets it through");
        assertFalse(ServiceAccountRiskExecutor.decide(answer("DENY", "DENY", "dry_run", false), null, false).refuse(), "dry_run lets it through");
        assertFalse(ServiceAccountRiskExecutor.decide(answer("DENY", "ALLOW", "enforce", true), null, false).refuse(), "advisory: nothing executed");
        assertFalse(ServiceAccountRiskExecutor.decide(answer("DISABLE_CLIENT", "ALLOW", "enforce", true), null, false).refuse());
        assertFalse(ServiceAccountRiskExecutor.decide(answer("ALLOW", "ALLOW", "enforce", false), null, false).refuse());

        ServiceAccountRiskExecutor.Decision noMode = ServiceAccountRiskExecutor.decide(answer("DENY", "DENY", null, false), null, false);
        assertEquals("enforce", noMode.mode(), "no mode in the answer: enforce, as for people");
        assertTrue(noMode.refuse());
    }

    private static HumifortisRiskEvaluator.ServiceAccountResult withActions(HumifortisRiskEvaluator.ServiceAccountResult a, String... actions) {
        a.decision().actions = List.of(actions);
        return a;
    }

    @Test
    void aClientThatAllowsItIsDisabledOnADecidedDisableAndRefused() {
        // HIGH: DISABLE_CLIENT enforced (the client declared it as an executor)
        ServiceAccountRiskExecutor.Decision high = ServiceAccountRiskExecutor.decide(
                withActions(answer("DISABLE_CLIENT", "DISABLE_CLIENT", "enforce", false), "DISABLE_CLIENT", "NOTIFY_SOC"), null, true);
        assertTrue(high.disable());
        assertTrue(high.refuse(), "a disabled client gets no token");

        // CRITICAL: DENY with DISABLE_CLIENT among the actions
        ServiceAccountRiskExecutor.Decision critical = ServiceAccountRiskExecutor.decide(
                withActions(answer("DENY", "DENY", "enforce", false), "DENY", "DISABLE_CLIENT", "NOTIFY_SOC"), null, true);
        assertTrue(critical.disable());
        assertTrue(critical.refuse());

        // the same CRITICAL for a client that does not allow it: refused, never disabled
        ServiceAccountRiskExecutor.Decision notAllowed = ServiceAccountRiskExecutor.decide(
                withActions(answer("DENY", "DENY", "enforce", false), "DENY", "DISABLE_CLIENT", "NOTIFY_SOC"), null, false);
        assertFalse(notAllowed.disable());
        assertTrue(notAllowed.refuse());

        // shadow: nothing is contained
        assertFalse(ServiceAccountRiskExecutor.decide(
                withActions(answer("DISABLE_CLIENT", "DISABLE_CLIENT", "shadow", false), "DISABLE_CLIENT"), null, true).disable());
        // advisory (not executed): nothing is contained
        assertFalse(ServiceAccountRiskExecutor.decide(
                withActions(answer("DISABLE_CLIENT", "ALLOW", "enforce", true), "DISABLE_CLIENT"), null, true).disable());
        // no answer: the fallback refuses at most
        assertFalse(ServiceAccountRiskExecutor.decide(noAnswer("timeout"), "deny", true).disable());
    }

    @Test
    void containmentNeedsTheClientsOptInAndHappensOnce() {
        ClientModel c = mock(ClientModel.class);
        assertEquals(ClientContainment.Result.NOT_ALLOWED, ClientContainment.disable(c, "analyst"));
        when(c.getAttribute(ClientContainment.ATTR_ALLOW_DISABLE)).thenReturn("true");
        when(c.getAttribute(ServiceAccountRiskExecutor.ATTR_ENFORCEMENT)).thenReturn("off");
        assertEquals(ClientContainment.Result.NOT_ALLOWED, ClientContainment.disable(c, "analyst"), "an exempt client is never disabled");
        when(c.getAttribute(ServiceAccountRiskExecutor.ATTR_ENFORCEMENT)).thenReturn(null);
        when(c.isEnabled()).thenReturn(true);
        assertEquals(ClientContainment.Result.DISABLED, ClientContainment.disable(c, "rule:sa_high_disable_client"));
        verify(c).setEnabled(false);
        verify(c).setAttribute(ClientContainment.ATTR_DISABLED_BY, "rule:sa_high_disable_client");
        verify(c).setAttribute(org.mockito.ArgumentMatchers.eq(ClientContainment.ATTR_DISABLED_AT), anyString());
        when(c.isEnabled()).thenReturn(false);
        assertEquals(ClientContainment.Result.ALREADY_DISABLED, ClientContainment.disable(c, "analyst"));
    }

    private static HumifortisRiskEvaluator.EvaluateResponse withNotEnforced(String... items) {
        HumifortisRiskEvaluator.EvaluateResponse r = new HumifortisRiskEvaluator.EvaluateResponse();
        r.not_enforced = new ArrayList<>();
        for (String it : items) {
            HumifortisRiskEvaluator.NotEnforcedItem n = new HumifortisRiskEvaluator.NotEnforcedItem();
            n.action = it.substring(0, it.indexOf(':'));
            n.reason = it.substring(it.indexOf(':') + 1);
            r.not_enforced.add(n);
        }
        return r;
    }

    @Test
    void theReportCopiesWhatCoreSaidWasNotEnforcedAndAddsOnlyTheModeThatLetTheRequestThrough() {
        // core's list is copied verbatim: a decided DISABLE_CLIENT the client did not allow
        assertEquals("DISABLE_CLIENT:client_not_opted_in",
                ServiceAccountRiskExecutor.notEnforced(withNotEnforced("DISABLE_CLIENT:client_not_opted_in"), "enforce", "ALLOW"));
        // nothing left out: an empty string, no key in the report
        assertEquals("", ServiceAccountRiskExecutor.notEnforced(withNotEnforced(), "enforce", "DENY"));
        assertEquals("", ServiceAccountRiskExecutor.notEnforced(null, "enforce", "ALLOW"));
        // shadow / dry run: the enforced DENY was not applied, said once with the mode
        assertEquals("DENY:mode_shadow", ServiceAccountRiskExecutor.notEnforced(withNotEnforced(), "shadow", "DENY"));
        assertEquals("DENY:mode_dry_run", ServiceAccountRiskExecutor.notEnforced(withNotEnforced(), "dry_run", "DENY"));
        // an ALLOW is never reported as not enforced, in any mode
        assertEquals("", ServiceAccountRiskExecutor.notEnforced(withNotEnforced(), "shadow", "ALLOW"));
        // both, in order, without duplicates
        assertEquals("DISABLE_CLIENT:client_not_opted_in,DENY:mode_shadow",
                ServiceAccountRiskExecutor.notEnforced(withNotEnforced("DISABLE_CLIENT:client_not_opted_in"), "shadow", "DENY"));
    }

    @Test
    void aClientThatDidNotAllowDisablingTellsCoreWhyTheActionIsNotCarriedOut() {
        assertEquals(Map.of("DISABLE_CLIENT", "client_not_opted_in"), ServiceAccountRiskExecutor.DECLINED_NOT_OPTED_IN);
    }

    @Test
    void withoutAnAnswerTheTokenIsIssuedUnlessTheClientSaysDeny() {
        ServiceAccountRiskExecutor.Decision open = ServiceAccountRiskExecutor.decide(noAnswer("timeout"), null, false);
        assertFalse(open.refuse(), "fail-open");
        assertEquals(DecisionReport.FALLBACK_APPLIED, open.reportType());
        assertEquals("ALLOW", open.enforced());

        ServiceAccountRiskExecutor.Decision closed = ServiceAccountRiskExecutor.decide(noAnswer("circuit_open"), "deny", false);
        assertTrue(closed.refuse());
        assertEquals("DENY", closed.enforced());
        assertFalse(ServiceAccountRiskExecutor.decide(noAnswer("timeout"), "allow", false).refuse());
    }

    @Test
    void theRefusalErrorOfThisStageIsRecognisedAndNothingElse() {
        assertTrue(ServiceAccountRiskExecutor.isRiskStageRefusal(true, "access_denied", Map.of("reason", "humifortis_risk")));
        assertFalse(ServiceAccountRiskExecutor.isRiskStageRefusal(true, "invalid_client_credentials", Map.of()), "a wrong secret stays a failure");
        assertFalse(ServiceAccountRiskExecutor.isRiskStageRefusal(true, "access_denied", Map.of("reason", "another_policy")), "another policy's refusal");
        assertFalse(ServiceAccountRiskExecutor.isRiskStageRefusal(false, "access_denied", Map.of("reason", "humifortis_risk")));
        assertFalse(ServiceAccountRiskExecutor.isRiskStageRefusal(true, "access_denied", null));
    }

    @Test
    void theScopesAreTheDefaultOnesPlusTheRequestedOptionalOnes() {
        ClientModel client = mock(ClientModel.class);
        // built before the stubbing: inToken stubs a mock itself
        Map<String, ClientScopeModel> defaults = Map.of("profile", inToken(true), "email", inToken(true), "roles", inToken(false), "web-origins", inToken(false));
        Map<String, ClientScopeModel> optional = Map.of("address", inToken(true), "phone", inToken(true));
        when(client.getClientScopes(true)).thenReturn(defaults);
        when(client.getClientScopes(false)).thenReturn(optional);
        assertEquals("email profile", ServiceAccountRiskExecutor.grantedScopes(client, null));
        assertEquals("address email profile", ServiceAccountRiskExecutor.grantedScopes(client, "address unknown"));
        when(client.getClientScopes(true)).thenReturn(Map.of());
        when(client.getClientScopes(false)).thenReturn(Map.of());
        assertNull(ServiceAccountRiskExecutor.grantedScopes(client, null));
    }

    private static ClientScopeModel inToken(boolean included) {
        ClientScopeModel m = mock(ClientScopeModel.class);
        when(m.isIncludeInTokenScope()).thenReturn(included);
        return m;
    }

    // ── executeOnEvent────────────────────────────────────────────────────────

    private record Sent(String type, String flowId, String requested, String enforced, String mode, Map<String, String> extra) {}

    private static final class Fixture {
        final KeycloakSession session = mock(KeycloakSession.class);
        final KeycloakContext ctx = mock(KeycloakContext.class);
        final RealmModel realm = mock(RealmModel.class);
        final ClientModel client = mock(ClientModel.class);
        final List<Sent> reports = new ArrayList<>();
        final List<List<String>> executorsSent = new ArrayList<>();
        final List<Map<String, String>> declinedSent = new ArrayList<>();
        HumifortisRiskEvaluator.ServiceAccountResult result;

        Fixture() {
            when(session.getContext()).thenReturn(ctx);
            when(ctx.getRealm()).thenReturn(realm);
            when(ctx.getClient()).thenReturn(client);
            when(realm.getId()).thenReturn("demo");
            when(realm.getName()).thenReturn("demo");
            when(client.getClientId()).thenReturn("billing-job");
            when(client.isServiceAccountsEnabled()).thenReturn(true);
            when(client.getClientScopes(true)).thenReturn(Map.of());
            when(client.getClientScopes(false)).thenReturn(Map.of());
        }

        ServiceAccountRiskExecutor executor() {
            return new ServiceAccountRiskExecutor(session,
                    (r, c, flowId, md, executors, declined) -> {
                        executorsSent.add(executors);
                        declinedSent.add(declined);
                        return result;
                    },
                    (type, entityId, flowId, r, requested, enforced, mode, extra) -> {
                        assertEquals("service_account:keycloak:demo:billing-job", entityId);
                        reports.add(new Sent(type, flowId, requested, enforced, mode, extra));
                    });
        }

        ClientPolicyContext tokenRequest() {
            UserSessionModel us = mock(UserSessionModel.class);
            when(us.getId()).thenReturn("sess-1");
            AuthenticatedClientSessionModel cs = mock(AuthenticatedClientSessionModel.class);
            when(cs.getUserSession()).thenReturn(us);
            return new ServiceAccountTokenRequestContext(new MultivaluedHashMap<>(), cs);
        }
    }

    private static boolean configured() {
        return tech.humifortis.keycloak.client.SaasConfig.fromEnv().hasApiKey();
    }

    @Test
    void otherClientPolicyEventsAreIgnored() throws Exception {
        Fixture f = new Fixture();
        ClientPolicyContext update = mock(ClientPolicyContext.class);
        when(update.getEvent()).thenReturn(ClientPolicyEvent.UPDATE);
        f.executor().executeOnEvent(update);
        assertTrue(f.reports.isEmpty());
        assertTrue(f.executorsSent.isEmpty());
    }

    @Test
    void anExemptClientIsNeverEvaluated() throws Exception {
        Fixture f = new Fixture();
        when(f.client.getAttribute(ServiceAccountRiskExecutor.ATTR_ENFORCEMENT)).thenReturn("off");
        f.executor().executeOnEvent(f.tokenRequest());
        assertTrue(f.executorsSent.isEmpty());
        verify(f.session, never()).setAttribute(anyString(), any());
    }

    @Test
    void aDenyIsRefusedReportedAndTheRequestMarkedEvaluated() throws Exception {
        if (!configured()) return; // the stage is off without an API key (covered by the e2e stack)
        Fixture f = new Fixture();
        f.result = answer("DENY", "DENY", "enforce", false);
        ClientPolicyException e = assertThrows(ClientPolicyException.class, () -> f.executor().executeOnEvent(f.tokenRequest()));
        assertEquals("access_denied", e.getError());
        assertEquals(ServiceAccountRiskExecutor.DENY_DESCRIPTION, e.getErrorDetail());
        assertEquals(List.of(List.of("DENY")), f.executorsSent);
        assertEquals(1, f.reports.size());
        assertEquals("sess-1", f.reports.get(0).flowId(), "the flow id is the request's session: one flow with its CLIENT_LOGIN");
        verify(f.session).setAttribute(ServiceAccountRiskExecutor.SESSION_ATTR_EVALUATED, Boolean.TRUE);
    }
}
