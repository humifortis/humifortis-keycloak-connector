package tech.humifortis.keycloak.auth;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.RealmModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.CommonClientSessionModel.ExecutionStatus;

class StepUpExecutionTest {

    private final Map<String, String> notes = new HashMap<>();
    private final Map<String, ExecutionStatus> executions = new HashMap<>();
    private AuthenticationSessionModel as;
    private RealmModel realm;

    @BeforeEach
    void setUp() {
        as = mock(AuthenticationSessionModel.class);
        realm = mock(RealmModel.class);
        lenient().when(as.getAuthNote(anyString())).thenAnswer(i -> notes.get((String) i.getArgument(0)));
        lenient().when(as.getExecutionStatus()).thenReturn(executions);
    }

    private void execution(String id, String authenticator, ExecutionStatus status) {
        AuthenticationExecutionModel e = new AuthenticationExecutionModel();
        e.setId(id);
        e.setAuthenticator(authenticator);
        when(realm.getAuthenticationExecutionById(id)).thenReturn(e);
        executions.put(id, status);
    }

    @Test
    void aStepUpDecisionWithoutAnyFactor_isSkipped() {
        notes.put(HumifortisRiskAuthenticator.NOTE_RISK_ACTION, "REQUIRE_MFA");
        assertTrue(StepUpExecution.skipped(as, realm));
    }

    @Test
    void theRouterRanAFactor_notSkipped() {
        notes.put(HumifortisRiskAuthenticator.NOTE_RISK_ACTION, "REQUIRE_TOTP");
        notes.put(HumifortisStepUpRouter.NOTE_MFA_METHOD, "TOTP");
        assertFalse(StepUpExecution.skipped(as, realm));
    }

    @Test
    void anotherSecondFactorCompletedInTheFlow_notSkipped() {
        notes.put(HumifortisRiskAuthenticator.NOTE_RISK_ACTION, "REQUIRE_MFA");
        execution("e1", "webauthn-authenticator", ExecutionStatus.SUCCESS);
        assertFalse(StepUpExecution.skipped(as, realm));
    }

    @Test
    void allowDenyOrNoDecision_notSkipped() {
        assertFalse(StepUpExecution.skipped(as, realm), "no decision note");
        notes.put(HumifortisRiskAuthenticator.NOTE_RISK_ACTION, "ALLOW");
        assertFalse(StepUpExecution.skipped(as, realm));
        notes.put(HumifortisRiskAuthenticator.NOTE_RISK_ACTION, "DENY");
        assertFalse(StepUpExecution.skipped(as, realm));
    }

    @Test
    void dryRunOrShadow_nothingWasToBeEnforced_notSkipped() {
        notes.put(HumifortisRiskAuthenticator.NOTE_RISK_ACTION, "REQUIRE_MFA");
        notes.put("humifortis_mode", "shadow");
        assertFalse(StepUpExecution.skipped(as, realm));
    }

    @Test
    void localDecisionSource_theRealmFlowDecides_notSkipped() {
        notes.put(HumifortisRiskAuthenticator.NOTE_RISK_ACTION, "REQUIRE_MFA");
        notes.put(ContextNotes.REPORT_MODE, "enforce");
        assertFalse(StepUpExecution.skipped(as, realm));
    }

    @Test
    void noAuthenticationSession_notSkipped() {
        assertFalse(StepUpExecution.skipped(null, realm));
    }
}
