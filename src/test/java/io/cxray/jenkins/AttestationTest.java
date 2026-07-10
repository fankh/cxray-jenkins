package io.cxray.jenkins;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.cxray.jenkins.local.Finding;
import io.cxray.jenkins.local.GateResult;
import java.util.Arrays;
import org.junit.Test;

public class AttestationTest {

    private final ObjectMapper m = new ObjectMapper();

    @Test
    public void buildsInTotoStatementWithSeveritiesAndVerdict() throws Exception {
        GateResult r = new GateResult("fail", Arrays.asList(
                new Finding("cve", "critical", "CVE-2024-0001", "base 9.8", 0),
                new Finding("license", "medium", "GPL-3.0", "deny", 0)));
        String json = Attestation.build(r, "api", "image IMG-1", "sha256:abc",
                "my-job", 42, "https://ci/job/my-job/42/", 1_700_000_000_000L);

        JsonNode n = m.readTree(json);
        assertEquals("https://in-toto.io/Statement/v1", n.get("_type").asText());
        assertEquals("https://cxray.io/attestations/gate/v1", n.get("predicateType").asText());
        assertEquals("image IMG-1", n.get("subject").get(0).get("name").asText());

        JsonNode pred = n.get("predicate");
        assertEquals("fail", pred.get("verdict").asText());
        assertTrue(pred.get("blocked").asBoolean());
        assertEquals(2, pred.get("findingCount").asInt());
        assertEquals(1, pred.get("severities").get("critical").asInt());
        assertEquals(1, pred.get("severities").get("medium").asInt());
        assertEquals("sha256:abc", pred.get("policyDigest").asText());
        assertEquals(42, pred.get("invocation").get("buildNumber").asInt());
        assertEquals("my-job", pred.get("invocation").get("job").asText());
    }

    @Test
    public void nullPolicyDigestIsExplicitNull() throws Exception {
        GateResult r = new GateResult("pass", java.util.Collections.emptyList());
        JsonNode n = m.readTree(Attestation.build(r, "local", "Modelfile", null, "j", 1, null, 1_700_000_000_000L));
        assertTrue(n.get("predicate").get("policyDigest").isNull());
        assertEquals("pass", n.get("predicate").get("verdict").asText());
    }
}
