package io.cxray.jenkins.api;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Base64;
import java.nio.charset.StandardCharsets;
import org.junit.Test;

/** Pure unit tests for the API auth format + gate normalization (no Jenkins harness). */
public class CxrayApiGateTest {

    private static final ObjectMapper M = new ObjectMapper();

    private static JsonNode j(String s) {
        try { return M.readTree(s); } catch (Exception e) { throw new RuntimeException(e); }
    }

    @Test
    public void bearerMatchesCliFormat() {
        String b = Auth.bearer("AK", "SK");
        String expected = "Bearer " + Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"accessKey\":\"AK\",\"secretKey\":\"SK\"}".getBytes(StandardCharsets.UTF_8));
        assertEquals(expected, b);
        String decoded = new String(Base64.getUrlDecoder().decode(b.substring(7)), StandardCharsets.UTF_8);
        assertEquals("{\"accessKey\":\"AK\",\"secretKey\":\"SK\"}", decoded);
    }

    @Test
    public void cveGate() {
        assertEquals("fail", CxrayApiGate.cve(j("{\"verdict\":\"fail\",\"kev\":[{\"cveCode\":\"CVE-1\",\"base\":10}]}")).verdict);
        assertEquals("pass", CxrayApiGate.cve(j("{\"verdict\":\"pass\"}")).verdict);
        // KEV code deduped from the critical list
        assertEquals(2, CxrayApiGate.cve(j("{\"verdict\":\"fail\",\"kev\":[{\"cveCode\":\"CVE-1\",\"base\":10}],"
                + "\"critical\":[{\"cveCode\":\"CVE-1\",\"base\":10},{\"cveCode\":\"CVE-2\",\"base\":9.8}]}")).findings.size());
    }

    @Test
    public void licenseGate() {
        assertEquals("fail", CxrayApiGate.license(j("{\"verdict\":\"fail\",\"deny\":[{\"name\":\"pkg\",\"licenses\":[\"AGPL-3.0\"]}]}")).verdict);
        assertEquals("review", CxrayApiGate.license(j("{\"verdict\":\"pass\",\"reviewCount\":3}")).verdict);
        assertEquals("pass", CxrayApiGate.license(j("{\"verdict\":\"pass\",\"reviewCount\":0}")).verdict);
    }

    @Test
    public void secretsAndAiPassthrough() {
        assertEquals("fail", CxrayApiGate.secrets(j("{\"verdict\":\"fail\",\"findings\":[{\"severity\":\"critical\",\"kind\":\"SSH key\",\"path\":\"/root\",\"fileName\":\"id_rsa\"}]}")).verdict);
        assertEquals("pass", CxrayApiGate.secrets(j("{\"verdict\":\"pass\",\"findings\":[]}")).verdict);
        assertEquals("review", CxrayApiGate.ai(j("{\"verdict\":\"review\",\"reviewArtifactCount\":2}")).verdict);
        assertTrue(CxrayApiGate.ai(j("{\"verdict\":\"fail\",\"unsafeArtifactCount\":1}")).findings.size() >= 1);
    }
}
