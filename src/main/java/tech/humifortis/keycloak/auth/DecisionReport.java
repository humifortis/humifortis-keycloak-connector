package tech.humifortis.keycloak.auth;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import tech.humifortis.keycloak.model.HumifortisEvent;

/**
 * What the connector did with the decision of one login, reported to Humifortis once, AFTER enforcement.
 *
 * <ul>
 *   <li>{@code decision_enforced}: Humifortis answered. The event carries what was asked ({@code requested_action}),
 *       what the flow applied ({@code enforced_action}), the mode, whether it was applied, and the outcome the person
 *       experienced: in {@code dry_run} and {@code shadow} the person is let in ({@code outcome = allow}) and
 *       {@code would_outcome} keeps what enforcement would have done.</li>
 *   <li>{@code decision_fallback_applied}: Humifortis could not answer; the connector's fallback policy decided.</li>
 * </ul>
 *
 * Sent through the connector's own queue, never through the Keycloak event bus: a decision is not a Keycloak error.
 */
public final class DecisionReport {

    public static final String DECISION_ENFORCED = "decision_enforced";
    public static final String FALLBACK_APPLIED = "decision_fallback_applied";

    /** The entity types a report is about. */
    public static final String USER = "user";
    public static final String SERVICE_ACCOUNT = "service_account";

    /** The three outcomes a person can experience. */
    public static final String ALLOW = "allow";
    public static final String STEP_UP = "step_up";
    public static final String DENY = "deny";

    private DecisionReport() {}

    /** The outcome of an action as the flow executes it (an unknown action is executed as an allow). */
    public static String outcomeOf(String action) {
        if (StepUpActions.isStepUp(action)) return STEP_UP;
        // a locked account, like a disabled client, gets nothing
        if ("DENY".equals(action) || "LOCK_ACCOUNT".equals(action) || "DISABLE_CLIENT".equals(action)) return DENY;
        return ALLOW;
    }

    /** Only {@code enforce} applies the decision; {@code dry_run} and {@code shadow} let the person in. */
    public static boolean applied(String mode) {
        return "enforce".equals(mode);
    }

    /**
     * @param type             {@link #DECISION_ENFORCED} or {@link #FALLBACK_APPLIED}
     * @param entityType       {@link #USER} or {@link #SERVICE_ACCOUNT}
     * @param requestedAction  the action decided (by Humifortis, or by the fallback policy)
     * @param enforcedAction   the action the flow applies after the factor fallback chain
     * @param extra            additional context (decision rule, fallback reason...), blank values are dropped
     */
    public static HumifortisEvent build(String type, String entityId, String entityType, String flowId, String realm,
                                        String requestedAction, String enforcedAction, String mode,
                                        Map<String, String> extra) {
        HumifortisEvent e = new HumifortisEvent();
        e.setEventId(UUID.randomUUID().toString());
        e.setEventType(type);
        e.setEntityId(entityId);
        e.setEntityType(entityType);
        e.setSource("keycloak-rba");
        e.setTimestamp(Instant.now().toString());
        e.setFlowId(flowId);
        String enforced = enforcedAction != null && !enforcedAction.isBlank() ? enforcedAction : requestedAction;
        boolean applied = applied(mode);
        String wouldOutcome = outcomeOf(enforced);
        e.addMetadata("realm", realm);
        e.addMetadata("requested_action", requestedAction);
        e.addMetadata("enforced_action", enforced);
        e.addMetadata("mode", mode);
        e.addMetadata("applied", String.valueOf(applied));
        e.addMetadata("outcome", applied ? wouldOutcome : ALLOW);
        e.addMetadata("would_outcome", wouldOutcome);
        if (StepUpActions.isStepUp(enforced)) e.addMetadata("step_up_action", enforced);
        if (extra != null) {
            extra.forEach((k, v) -> {
                if (v != null && !v.isBlank()) e.addMetadata(k, v);
            });
        }
        return e;
    }
}
