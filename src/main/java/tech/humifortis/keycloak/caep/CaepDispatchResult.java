package tech.humifortis.keycloak.caep;

public record CaepDispatchResult(
        String processingResult,
        String action,
        String error
) {
    public static CaepDispatchResult success(String action) {
        return new CaepDispatchResult("processed", action, "");
    }

    public static CaepDispatchResult noAction(String reason) {
        return new CaepDispatchResult("ignored", "none", reason);
    }

    public static CaepDispatchResult failed(String action, String reason) {
        return new CaepDispatchResult("enforcement_failed", action, reason);
    }
}
