package tech.humifortis.keycloak.token;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;

/**
 * The chain of delegations a token carries (docs/sso-and-external-idp-e2e.spec.md, P21, AG-3 and AG-6..AG-8): RFC 8693 puts
 * the actor that acts for the subject in the {@code act} claim, and an actor that itself acts for another one nests its own
 * {@code act} inside. Read outermost first, the chain says who holds the token now and who they act for.
 *
 * <p>The connector reads it and reports its shape (depth, a loop, an actor nobody registered); the rules of Humifortis judge
 * the shape and the tenant sets the limit. Nothing here decides.</p>
 */
public final class DelegationChain {

    public static final String KEY_DEPTH = "delegation.depth";
    public static final String KEY_LOOP = "delegation.has_loop";
    public static final String KEY_UNKNOWN_ACTOR = "delegation.has_unknown_actor";
    public static final String KEY_ACTORS = "delegation.actors";

    /** A chain longer than this is cut: the facts it gives are the same and the report stays small. */
    static final int MAX_READ = 20;

    private final List<String> actors;

    private DelegationChain(List<String> actors) {
        this.actors = actors;
    }

    /** The chain of a token's claims: its {@code act} claim, followed down. An absent or malformed claim is an empty chain. */
    public static DelegationChain of(Map<String, Object> claims) {
        List<String> actors = new ArrayList<>();
        Object act = claims != null ? claims.get("act") : null;
        while (act instanceof Map<?, ?> map && actors.size() < MAX_READ) {
            Object id = map.get("sub") != null ? map.get("sub") : map.get("client_id");
            actors.add(id != null && !id.toString().isBlank() ? id.toString().trim() : "?");
            act = map.get("act");
        }
        return new DelegationChain(actors);
    }

    public List<String> actors() {
        return actors;
    }

    /** The number of actors: a person acted for by one agent is 1. */
    public int depth() {
        return actors.size();
    }

    /** Whether an actor appears twice. */
    public boolean hasLoop() {
        return new HashSet<>(actors).size() != actors.size();
    }

    /** The first actor that is not registered, or null. {@code registered} is asked for each actor's identifier. */
    public String firstUnknown(Predicate<String> registered) {
        Set<String> seen = new HashSet<>();
        for (String a : actors) {
            if (seen.add(a) && !registered.test(a)) return a;
        }
        return null;
    }

    /** The facts of the chain for the evaluation; empty when the token carries no delegation. */
    public Map<String, String> facts(Predicate<String> registered) {
        Map<String, String> out = new LinkedHashMap<>();
        if (actors.isEmpty()) return out;
        out.put(KEY_DEPTH, String.valueOf(depth()));
        out.put(KEY_LOOP, String.valueOf(hasLoop()));
        String unknown = firstUnknown(registered);
        out.put(KEY_UNKNOWN_ACTOR, String.valueOf(unknown != null));
        String chain = String.join(">", actors);
        out.put(KEY_ACTORS, unknown != null ? chain + "; unknown=" + unknown : chain);
        return out;
    }
}
