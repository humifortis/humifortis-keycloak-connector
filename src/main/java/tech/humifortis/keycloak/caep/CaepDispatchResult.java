package tech.humifortis.keycloak.caep;

import java.util.Map;

public record CaepDispatchResult(
        String processingResult,
        String action,
        String error,
        Map<String, Object> detail
) {
    public CaepDispatchResult(String processingResult, String action, String error) {
        this(processingResult, action, error, null);
    }

    /** A processed event that reports what it did (a recovery lists the credentials it removed). */
    public static CaepDispatchResult success(String action, Map<String, Object> detail) {
        return new CaepDispatchResult("processed", action, "", detail);
    }

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
