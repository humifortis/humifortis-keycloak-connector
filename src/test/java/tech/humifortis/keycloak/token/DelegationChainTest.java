package tech.humifortis.keycloak.token;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

class DelegationChainTest {

    private static Map<String, Object> act(String sub, Map<String, Object> inner) {
        return inner == null ? Map.of("sub", sub) : Map.of("sub", sub, "act", inner);
    }

    private static final Set<String> REGISTERED = Set.of("agent-a", "agent-b", "agent-c");

    @Test
    void noActClaimIsNoDelegation() {
        DelegationChain chain = DelegationChain.of(Map.of("sub", "alice"));
        assertEquals(0, chain.depth());
        assertTrue(chain.facts(REGISTERED::contains).isEmpty(), "nothing is reported for a token that is not delegated");
        assertEquals(0, DelegationChain.of(null).depth());
        assertEquals(0, DelegationChain.of(Map.of("act", "not-a-map")).depth(), "a malformed claim is an empty chain");
    }

    @Test
    void anAgentActingForAPersonIsOneHop() {
        DelegationChain chain = DelegationChain.of(Map.of("sub", "alice", "act", act("agent-a", null)));
        assertEquals(1, chain.depth());
        assertEquals(List.of("agent-a"), chain.actors());
        assertFalse(chain.hasLoop());
        Map<String, String> facts = chain.facts(REGISTERED::contains);
        assertEquals("1", facts.get(DelegationChain.KEY_DEPTH));
        assertEquals("false", facts.get(DelegationChain.KEY_LOOP));
        assertEquals("false", facts.get(DelegationChain.KEY_UNKNOWN_ACTOR));
        assertEquals("agent-a", facts.get(DelegationChain.KEY_ACTORS));
    }

    @Test
    void theChainIsReadOutermostFirst() {
        Map<String, Object> claims = Map.of("sub", "alice", "act", act("agent-c", act("agent-b", act("agent-a", null))));
        DelegationChain chain = DelegationChain.of(claims);
        assertEquals(List.of("agent-c", "agent-b", "agent-a"), chain.actors());
        assertEquals(3, chain.depth(), "a person, and three agents acting one for another");
        assertEquals("agent-c>agent-b>agent-a", chain.facts(REGISTERED::contains).get(DelegationChain.KEY_ACTORS));
    }

    @Test
    void anActorTwiceIsALoop() {
        DelegationChain chain = DelegationChain.of(Map.of("act", act("agent-a", act("agent-b", act("agent-a", null)))));
        assertTrue(chain.hasLoop());
        assertEquals("true", chain.facts(REGISTERED::contains).get(DelegationChain.KEY_LOOP));
    }

    @Test
    void theFirstActorNobodyRegisteredIsNamed() {
        DelegationChain chain = DelegationChain.of(Map.of("act", act("agent-a", act("rogue", act("rogue-2", null)))));
        assertEquals("rogue", chain.firstUnknown(REGISTERED::contains));
        Map<String, String> facts = chain.facts(REGISTERED::contains);
        assertEquals("true", facts.get(DelegationChain.KEY_UNKNOWN_ACTOR));
        assertEquals("agent-a>rogue>rogue-2; unknown=rogue", facts.get(DelegationChain.KEY_ACTORS));
        assertNull(DelegationChain.of(Map.of("act", act("agent-a", null))).firstUnknown(REGISTERED::contains));
    }

    @Test
    void aClaimThatNeverEndsIsCut() {
        Map<String, Object> deep = act("agent-a", null);
        for (int i = 0; i < 50; i++) deep = act("agent-" + i, deep);
        assertEquals(DelegationChain.MAX_READ, DelegationChain.of(Map.of("act", deep)).depth());
    }
}
