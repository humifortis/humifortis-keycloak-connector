package tech.humifortis.keycloak.user;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import tech.humifortis.keycloak.user.LiveSessions.Entry;

class LiveSessionsTest {

    private static final long NOW = 10_000L;

    @Test
    void anEntryIsAddressAgeIdlePlatformAndUserAgent() {
        String out = LiveSessions.format(List.of(new Entry("81.2.69.142", NOW - 120, NOW - 30, "Linux", "Mozilla/5.0 (X11; Linux x86_64) Chrome/130")), NOW);
        assertEquals("81.2.69.142|120|30|Linux|Mozilla/5.0 (X11; Linux x86_64) Chrome/130", out);
    }

    @Test
    void noSeparatorOfTheListCanBeForgedThroughAField() {
        String out = LiveSessions.format(List.of(new Entry("1.2.3.4", NOW, NOW, "Win|dows,", "UA, with | and\nnewline")), NOW);
        assertFalse(out.contains(","), "one entry");
        assertEquals(4, out.chars().filter(c -> c == '|').count(), "five fields, no more");
        assertFalse(out.contains("\n"));
    }

    @Test
    void theYoungestAreKeptWhenThereAreTooMany() {
        List<Entry> all = new ArrayList<>();
        for (int i = 0; i < LiveSessions.MAX + 10; i++) all.add(new Entry("1.2.3." + (i % 250), NOW - 1000 + i, NOW, "", ""));
        String[] parts = LiveSessions.format(all, NOW).split(",");
        assertEquals(LiveSessions.MAX, parts.length);
        assertTrue(parts[0].startsWith("1.2.3." + ((LiveSessions.MAX + 9) % 250) + "|"), "the youngest first");
    }

    @Test
    void aSessionWithoutAnAddressIsLeftOut() {
        assertEquals("", LiveSessions.format(List.of(new Entry(null, NOW, NOW, "", ""), new Entry(" ", NOW, NOW, "", "")), NOW));
    }

    @Test
    void aClockBehindTheSessionNeverGivesANegativeAge() {
        assertEquals("1.2.3.4|0|0||", LiveSessions.format(List.of(new Entry("1.2.3.4", NOW + 50, NOW + 50, null, null)), NOW));
    }

    @Test
    void aLongUserAgentIsBounded() {
        String out = LiveSessions.format(List.of(new Entry("1.2.3.4", NOW, NOW, "", "x".repeat(1000))), NOW);
        assertEquals(160, out.substring(out.lastIndexOf('|') + 1).length());
    }
}
