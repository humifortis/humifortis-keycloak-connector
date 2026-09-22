package tech.humifortis.keycloak.caep;

import com.google.gson.JsonObject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import tech.humifortis.keycloak.HumifortisCache;

import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

@Path("")
public class CaepReceiverResource {
    private static final Logger LOG = Logger.getLogger(CaepReceiverResource.class);

    private final KeycloakSession session;
    private final CaepSetValidator validator;
    private final CaepReplayGuard replayGuard;
    private final CaepEventRegistry registry;
    private final Clock clock;

    public CaepReceiverResource(KeycloakSession session) {
        this(session, new CaepSetValidator(new HttpCaepJwksFetcher(), Clock.systemUTC()), new CaepReplayGuard(HumifortisCache.getInstance()), new CaepEventRegistry(), Clock.systemUTC());
    }

    CaepReceiverResource(KeycloakSession session, CaepSetValidator validator, CaepReplayGuard replayGuard, CaepEventRegistry registry, Clock clock) {
        this.session = session;
        this.validator = validator;
        this.replayGuard = replayGuard;
        this.registry = registry;
        this.clock = clock;
    }

    @POST
    @Path("caep/events")
    @Consumes({"application/secevent+jwt", MediaType.TEXT_PLAIN})
    @Produces(MediaType.APPLICATION_JSON)
    public Response receive(String token) {
        RealmModel realm = session.getContext().getRealm();
        if (realm == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity(Map.of("error", "Realm context unavailable")).build();
        }
        CaepConfig config = CaepConfig.fromRealm(realm);
        if (!config.enabled()) {
            return Response.status(Response.Status.BAD_REQUEST).entity(Map.of("error", "CAEP receiver disabled")).build();
        }

        Instant receivedAt = clock.instant();
        CaepParsedSet set;
        try {
            set = validator.validate(token, config);
        } catch (CaepValidationException e) {
            audit(new CaepAuditRecord(
                    "",
                    "",
                    realm.getName(),
                    "",
                    "",
                    "",
                    "",
                    receivedAt.toString(),
                    "",
                    "rejected",
                    "rejected",
                    "none",
                    e.getMessage()
            ));
            return Response.status(e.getStatusCode()).entity(Map.of("error", e.getMessage())).build();
        }

        if (replayGuard.isReplay(realm.getId(), set.jti(), config)) {
            audit(buildAudit(set, realm, "replay", "ignored", "none", "duplicate jti", receivedAt, "", ""));
            return Response.ok(Map.of("status", "replay")).build();
        }

        CaepActionDispatcher dispatcher = new CaepActionDispatcher(session);
        boolean hasProcessed = false;
        boolean hasFailure = false;
        Set<String> actions = new LinkedHashSet<>();
        Set<String> errors = new LinkedHashSet<>();

        for (Map.Entry<String, com.google.gson.JsonElement> eventEntry : set.events().entrySet()) {
            String eventUri = eventEntry.getKey();
            String eventName = registry.resolve(eventUri);
            if (eventName == null) {
                audit(buildAudit(set, realm, "valid", "ignored", "none", "unsupported event: " + eventUri, receivedAt, eventUri, extractDecisionId(eventEntry.getValue())));
                continue;
            }
            if (!registry.isEnabled(eventName, config)) {
                audit(buildAudit(set, realm, "valid", "ignored", "none", "disabled event: " + eventName, receivedAt, eventName, extractDecisionId(eventEntry.getValue())));
                continue;
            }

            CaepDispatchResult result = dispatcher.dispatch(eventName, set, config, realm);
            audit(buildAudit(set, realm, "valid", result.processingResult(), result.action(), result.error(), receivedAt, eventName, extractDecisionId(eventEntry.getValue())));
            if ("processed".equals(result.processingResult())) hasProcessed = true;
            if ("enforcement_failed".equals(result.processingResult())) hasFailure = true;
            if (result.action() != null && !result.action().isBlank() && !"none".equals(result.action())) actions.add(result.action());
            if (result.error() != null && !result.error().isBlank()) errors.add(result.error());
        }

        String finalProcessing = hasFailure ? "enforcement_failed" : (hasProcessed ? "processed" : "ignored");
        String finalAction = actions.isEmpty() ? "none" : String.join(",", actions);
        String finalError = errors.isEmpty() ? "" : String.join(" | ", errors);

        return Response.ok(Map.of(
                "status", "accepted",
                "processing", finalProcessing,
                "action", finalAction,
                "error", finalError
        )).build();
    }

    private CaepAuditRecord buildAudit(
            CaepParsedSet set,
            RealmModel realm,
            String validationResult,
            String processingResult,
            String action,
            String error,
            Instant receivedAt,
            String eventType,
            String decisionId) {
        return new CaepAuditRecord(
                set.jti(),
                set.issuer(),
                realm.getName(),
                eventType,
                set.subject(),
                set.sessionId(),
                decisionId,
                receivedAt.toString(),
                set.issuedAt().toString(),
                validationResult,
                processingResult,
                action,
                error
        );
    }

    private String extractDecisionId(com.google.gson.JsonElement eventPayload) {
        if (eventPayload == null || !eventPayload.isJsonObject()) return "";
        JsonObject obj = eventPayload.getAsJsonObject();
        if (obj.has("decision_id")) return obj.get("decision_id").getAsString();
        if (obj.has("decisionId")) return obj.get("decisionId").getAsString();
        if (obj.has("id")) return obj.get("id").getAsString();
        return "";
    }

    private void audit(CaepAuditRecord record) {
        CaepAuditLogger.log(record);
        LOG.debugf("CAEP audit: jti=%s realm=%s event=%s processing=%s",
                record.jti(), record.realm(), record.eventType(), record.processingResult());
    }
}
