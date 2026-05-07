package tech.humifortis.keycloak.auth;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import tech.humifortis.keycloak.client.SaasClient;
import tech.humifortis.keycloak.client.SaasConfig;
import tech.humifortis.keycloak.model.RiskDecision;

public class HumifortisRBAAuthenticator implements Authenticator {
    private static final Logger logger = Logger.getLogger(HumifortisRBAAuthenticator.class);
    
    private SaasClient saasClient;
    private boolean fallbackAllow;

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        // Initialize client if not already done
        if (saasClient == null) {
            try {
                SaasConfig config = new SaasConfig();
                saasClient = new SaasClient(config);
                fallbackAllow = config.isFallbackAllow();
                logger.info("Humifortis RBA Authenticator initialized");
            } catch (Exception e) {
                logger.error("Failed to initialize SaaS client", e);
                handleFallback(context, "Configuration error");
                return;
            }
        }

        UserModel user = context.getUser();
        if (user == null) {
            logger.warn("RBA check skipped: no user in context");
            context.success();
            return;
        }

        String entityId = generateEntityId(context, user);
        
        // Ask SaaS: What should I do?
        RiskDecision decision;
        try {
            decision = saasClient.getRiskDecision(entityId);
            logger.debugf("RBA decision received for %s: %s (risk: %s)", 
                    entityId, decision.getAction(), decision.getRiskScore());
            // Store risk decision in auth session notes and event details for feedback
            context.getAuthenticationSession().setAuthNote("HUMIFORTIS_RISK_SCORE", decision.getRiskScore() != null ? decision.getRiskScore().toString() : "");
            context.getAuthenticationSession().setAuthNote("HUMIFORTIS_RISK_LEVEL", decision.getRiskLevel() != null ? decision.getRiskLevel() : "");
            context.getAuthenticationSession().setAuthNote("HUMIFORTIS_RISK_ACTION", decision.getAction() != null ? decision.getAction().name() : "");
            context.getAuthenticationSession().setAuthNote("HUMIFORTIS_RISK_REASON", decision.getReason() != null ? decision.getReason() : "");

            // Also store in event details for EventListener feedback
            if (context.getEvent() != null) {
                context.getEvent().detail("HUMIFORTIS_RISK_SCORE", decision.getRiskScore() != null ? decision.getRiskScore().toString() : "");
                context.getEvent().detail("HUMIFORTIS_RISK_LEVEL", decision.getRiskLevel() != null ? decision.getRiskLevel() : "");
                context.getEvent().detail("HUMIFORTIS_RISK_ACTION", decision.getAction() != null ? decision.getAction().name() : "");
                context.getEvent().detail("HUMIFORTIS_RISK_REASON", decision.getReason() != null ? decision.getReason() : "");
            }
        } catch (Exception e) {
            logger.errorf("Failed to get decision from SaaS for %s: %s", entityId, e.getMessage());
            handleFallback(context, "Service unavailable");
            return;
        }

        // Enforce decision (no local logic!)
        switch (decision.getAction()) {
            case ALLOW:
                logger.debugf("RBA: Allow login for %s", entityId);
                context.success();
                break;

            case CHALLENGE_MFA:
                logger.infof("RBA: Challenge MFA for %s (risk: %s)", 
                        entityId, decision.getRiskScore());
                // This will force the next authenticator in the flow (typically OTP/WebAuthn)
                context.attempted();
                break;

            case BLOCK:
                logger.warnf("RBA: Block login for %s (risk: %s, reason: %s)", 
                        entityId, decision.getRiskScore(), decision.getReason());

                // Send block event back to SaaS
                saasClient.sendBlockEventAsync(entityId, decision)
                        .exceptionally(ex -> {
                            logger.warn("Failed to send block event to SaaS", ex);
                            return null;
                        });

                // Set risk block marker for event listener feedback
                context.getAuthenticationSession().setAuthNote("HUMIFORTIS_RISK_BLOCKED", "true");

                // Deny access and show error page
                context.failure(AuthenticationFlowError.ACCESS_DENIED);
                context.forceChallenge(createBlockedPage(context, decision));
                break;
        }
    }

    private String generateEntityId(AuthenticationFlowContext context, UserModel user) {
        // Format: user:keycloak:{realmId}:{userId}
        String realmId = context.getRealm().getId();
        String userId = user.getId() != null ? user.getId() : user.getUsername();
        return String.format("user:keycloak:%s:%s", realmId, userId);
    }

    private void handleFallback(AuthenticationFlowContext context, String reason) {
        if (fallbackAllow) {
            logger.warnf("RBA fallback: allowing access due to %s", reason);
            context.success();
        } else {
            logger.warnf("RBA fallback: blocking access due to %s", reason);
            context.failure(AuthenticationFlowError.ACCESS_DENIED);
            Response response = context.form()
                    .setError("Access temporarily unavailable. Please try again later.")
                    .createErrorPage(Response.Status.SERVICE_UNAVAILABLE);
            context.forceChallenge(response);
        }
    }

    private Response createBlockedPage(AuthenticationFlowContext context, RiskDecision decision) {
        LoginFormsProvider form = context.form();
        
        String message = decision.getMessageToUser() != null 
                ? decision.getMessageToUser() 
                : "Your account has been temporarily locked due to suspicious activity.";
        
        form.setError("access_denied");
        form.setAttribute("errorMessage", message);
        
        if (decision.getReason() != null) {
            form.setAttribute("reason", decision.getReason());
        }
        
        if (decision.getRiskScore() != null) {
            form.setAttribute("riskScore", decision.getRiskScore());
        }
        
        return form.createErrorPage(Response.Status.FORBIDDEN);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // Not used for this authenticator
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // No required actions
    }

    @Override
    public void close() {
        // Nothing to close
    }
}
