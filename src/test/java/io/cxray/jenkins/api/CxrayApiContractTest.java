package io.cxray.jenkins.api;

import static org.junit.Assert.assertEquals;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.cxray.jenkins.local.GateResult;
import org.junit.Test;

/**
 * Contract test: feeds the <em>full, real-shaped</em> responses emitted by the cxray-main gate
 * controllers (CveGateService / AiSupplyChainService / LicensePolicyService / SecretsExposureService)
 * — every field the server sends, not a minimal subset — through {@link CxrayApiGate}, and locks the
 * verdict + finding mapping. Keeps the plugin and the backend in lock-step; if the server shape
 * drifts, this fails. Mirrors the same normalization the cxray-gate CLI uses.
 */
public class CxrayApiContractTest {

    private final ObjectMapper m = new ObjectMapper();

    private JsonNode json(String s) throws Exception {
        return m.readTree(s);
    }

    @Test
    public void cveGate_realShape_failsOnKevAndCritical() throws Exception {
        // CveGateService.evaluate(...) shape
        GateResult g = CxrayApiGate.cve(json("{"
                + "\"imageId\":\"IMG\",\"verdict\":\"fail\",\"blocked\":true,"
                + "\"distinctCveCount\":12,\"kevCount\":1,\"criticalCount\":2,"
                + "\"kev\":[{\"cveCode\":\"CVE-2024-0001\",\"base\":9.8}],"
                + "\"critical\":[{\"cveCode\":\"CVE-2024-0001\",\"base\":9.8},{\"cveCode\":\"CVE-2024-0002\",\"base\":9.1}],"
                + "\"policy\":{\"failOnKev\":true,\"maxCvss\":9.0}}"));
        assertEquals("fail", g.verdict);
        // KEV finding + the one critical that isn't already a KEV (0001 is deduped)
        assertEquals(2, g.findings.size());
    }

    @Test
    public void cveGate_realShape_passesWhenEmpty() throws Exception {
        GateResult g = CxrayApiGate.cve(json("{"
                + "\"imageId\":\"IMG\",\"verdict\":\"pass\",\"blocked\":false,"
                + "\"distinctCveCount\":3,\"kevCount\":0,\"criticalCount\":0,"
                + "\"kev\":[],\"critical\":[],\"policy\":{\"failOnKev\":true,\"maxCvss\":9.0}}"));
        assertEquals("pass", g.verdict);
        assertEquals(0, g.findings.size());
    }

    @Test
    public void licenseGate_realShape_failsOnDeny() throws Exception {
        // LicensePolicyService shape (server emits pass|fail; plugin derives review from reviewCount)
        GateResult g = CxrayApiGate.license(json("{"
                + "\"imageId\":\"IMG\",\"verdict\":\"fail\",\"componentCount\":40,"
                + "\"denyCount\":1,\"reviewCount\":1,"
                + "\"deny\":[{\"name\":\"gpl-lib\",\"version\":\"1.0\",\"licenses\":[\"GPL-3.0\"]}],"
                + "\"review\":[{\"name\":\"weak-lib\",\"version\":\"2.0\",\"licenses\":[\"LGPL-3.0\"]}]}"));
        assertEquals("fail", g.verdict);
        assertEquals(2, g.findings.size());
    }

    @Test
    public void licenseGate_realShape_reviewWhenOnlyReviewListed() throws Exception {
        GateResult g = CxrayApiGate.license(json("{"
                + "\"imageId\":\"IMG\",\"verdict\":\"pass\",\"componentCount\":40,"
                + "\"denyCount\":0,\"reviewCount\":2,\"deny\":[],"
                + "\"review\":[{\"name\":\"a\",\"version\":\"1\",\"licenses\":[\"LGPL-3.0\"]},"
                + "{\"name\":\"b\",\"version\":\"1\",\"licenses\":[\"MPL-2.0\"]}]}"));
        assertEquals("review", g.verdict);
        assertEquals(2, g.findings.size());
    }

    @Test
    public void secretsGate_realShape_failsWithFindings() throws Exception {
        // SecretsExposureService shape
        GateResult g = CxrayApiGate.secrets(json("{"
                + "\"imageId\":\"IMG\",\"verdict\":\"fail\",\"count\":1,"
                + "\"criticalCount\":0,\"highCount\":1,\"mediumCount\":0,"
                + "\"findings\":[{\"path\":\"app\",\"fileName\":\".env\",\"kind\":\"aws-key\","
                + "\"severity\":\"high\",\"worldReadable\":true}]}"));
        assertEquals("fail", g.verdict);
        assertEquals(1, g.findings.size());
    }

    @Test
    public void aiGate_realShape_failsOnUnsafeArtifacts() throws Exception {
        // AiSupplyChainService shape
        GateResult g = CxrayApiGate.ai(json("{"
                + "\"imageId\":\"IMG\",\"verdict\":\"fail\",\"aiLibCount\":5,"
                + "\"modelArtifactCount\":3,\"unsafeArtifactCount\":2,\"reviewArtifactCount\":1,"
                + "\"aiLibraries\":[{\"name\":\"torch\",\"version\":\"2.3\",\"category\":\"framework\",\"risk\":\"safe\"}],"
                + "\"modelArtifacts\":[{\"path\":\"m\",\"fileName\":\"model.pt\",\"ext\":\"pt\",\"format\":\"pickle\",\"risk\":\"unsafe\"}]}"));
        assertEquals("fail", g.verdict);
    }

    @Test
    public void mcpGate_realShape_failsWithNonPassRules() throws Exception {
        // PolicyGateService.evaluate(...) shape
        GateResult g = CxrayApiGate.mcp(json("{"
                + "\"serverId\":\"svc\",\"version\":\"v1\",\"verdict\":\"fail\",\"blocked\":true,"
                + "\"policyPackVersion\":\"2026.1\",\"rules\":["
                + "{\"id\":\"poisoning\",\"title\":\"No tool-descriptor poisoning\",\"owasp\":\"ASI01 Agentic Prompt Injection\",\"status\":\"fail\",\"detail\":\"1 injection signal(s)\"},"
                + "{\"id\":\"exfil\",\"title\":\"No exfiltration\",\"owasp\":\"ASI04\",\"status\":\"review\",\"detail\":\"1 exfil signal(s)\"},"
                + "{\"id\":\"drift\",\"title\":\"No integrity drift since pin\",\"owasp\":\"ASI04\",\"status\":\"pass\",\"detail\":\"ok\"}]}"));
        assertEquals("fail", g.verdict);
        assertEquals(2, g.findings.size()); // the two non-pass rules
    }

    @Test
    public void aiGate_realShape_reviewWhenOnlyReviewArtifacts() throws Exception {
        GateResult g = CxrayApiGate.ai(json("{"
                + "\"imageId\":\"IMG\",\"verdict\":\"review\",\"aiLibCount\":2,"
                + "\"modelArtifactCount\":1,\"unsafeArtifactCount\":0,\"reviewArtifactCount\":1,"
                + "\"aiLibraries\":[],\"modelArtifacts\":[]}"));
        assertEquals("review", g.verdict);
    }
}
