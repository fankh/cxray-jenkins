package io.cxray.jenkins;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.cxray.jenkins.local.Finding;
import io.cxray.jenkins.local.GateResult;
import java.util.Arrays;
import org.junit.Test;

public class SarifTest {

    private final ObjectMapper m = new ObjectMapper();

    @Test
    public void buildsValidSarif210WithResultsAndProperties() throws Exception {
        GateResult r = new GateResult("fail", Arrays.asList(
                new Finding("cve", "critical", "CVE-2024-0001", "base 9.8 · KEV", 0),
                new Finding("license", "medium", "GPL-3.0", "deny", 0)));
        JsonNode n = m.readTree(Sarif.build(r, "api", "image IMG-1", "1.0.0"));

        assertEquals("2.1.0", n.get("version").asText());
        JsonNode run = n.get("runs").get(0);
        assertEquals("CXRay Security Gate", run.get("tool").get("driver").get("name").asText());
        assertEquals(2, run.get("tool").get("driver").get("rules").size()); // cve + license

        JsonNode results = run.get("results");
        assertEquals(2, results.size());
        JsonNode first = results.get(0);
        assertEquals("cve", first.get("ruleId").asText());
        assertEquals("error", first.get("level").asText());                       // critical -> error
        assertTrue(first.get("properties").get("frameworks").asText().contains("OWASP"));
        assertEquals("warning", results.get(1).get("level").asText());            // medium -> warning
        assertEquals("fail", run.get("properties").get("verdict").asText());
    }

    @Test
    public void emptyFindingsProducesEmptyResults() throws Exception {
        JsonNode n = m.readTree(Sarif.build(new GateResult("pass", java.util.Collections.emptyList()),
                "local", "Modelfile", null));
        assertEquals(0, n.get("runs").get(0).get("results").size());
    }
}
