package io.cxray.jenkins.local;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Arrays;
import org.junit.Test;

public class SuggestionsTest {

    private final ObjectMapper m = new ObjectMapper();

    @Test
    public void vexHasNotAffectedStatementPerDistinctCve() throws Exception {
        JsonNode n = m.readTree(Suggestions.vex(Arrays.asList(
                new Finding("cve", "critical", "CVE-2024-0001", "base 9.8", 0),
                new Finding("cve", "critical", "CVE-2024-0001", "dup", 0),   // deduped
                new Finding("license", "medium", "GPL-3.0", "deny", 0))));    // not a CVE
        JsonNode st = n.get("statements");
        assertEquals(1, st.size());
        assertEquals("CVE-2024-0001", st.get(0).get("vulnerability").get("name").asText());
        assertEquals("not_affected", st.get(0).get("status").asText());
    }

    @Test
    public void waiversCoverNonCveFindingsOnly() throws Exception {
        JsonNode n = m.readTree(Suggestions.waivers(Arrays.asList(
                new Finding("cve", "critical", "CVE-2024-0001", "base 9.8", 0),   // excluded (VEX)
                new Finding("poison", "high", "hidden-instruction", "x", 0),
                new Finding("secrets", "high", "aws-key", ".env", 0))));
        JsonNode arr = n.get("waivers");
        assertEquals(2, arr.size());
        assertEquals("poison", arr.get(0).get("check").asText());
        assertTrue(arr.get(0).get("reason").asText().toLowerCase().contains("justify"));
    }

    @Test
    public void emptyFindingsProduceEmptyStanzas() throws Exception {
        assertEquals(0, m.readTree(Suggestions.vex(java.util.Collections.emptyList())).get("statements").size());
        assertEquals(0, m.readTree(Suggestions.waivers(java.util.Collections.emptyList())).get("waivers").size());
    }
}
