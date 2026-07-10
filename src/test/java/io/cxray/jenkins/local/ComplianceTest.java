package io.cxray.jenkins.local;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class ComplianceTest {

    @Test
    public void poisonMapsToAsi01() {
        assertTrue(Compliance.frameworks("poison", "hidden instruction").contains("ASI01"));
        assertTrue(Compliance.remediation("poison", "x").toLowerCase().contains("tool description"));
    }

    @Test
    public void toxicCapabilityMapsToAsi03() {
        assertTrue(Compliance.frameworks("capability", "exec+network").contains("ASI03"));
    }

    @Test
    public void unsafeModelRemediationSuggestsSafetensors() {
        String r = Compliance.remediation("model", "unsafe pickle serialization").toLowerCase();
        assertTrue(r.contains("safetensors"));
    }

    @Test
    public void secretsMapsToCweAndRotation() {
        assertTrue(Compliance.frameworks("secrets", "aws-key").contains("CWE-798"));
        assertTrue(Compliance.remediation("secrets", "aws-key").toLowerCase().contains("rotate"));
    }

    @Test
    public void everyKnownCheckHasNonEmptyMapping() {
        for (String c : new String[]{"transport", "identity", "model", "poison", "capability",
                "ai", "cve", "license", "secrets", "unknown-check"}) {
            assertFalse("frameworks empty for " + c, Compliance.frameworks(c, "").isEmpty());
            assertFalse("remediation empty for " + c, Compliance.remediation(c, "").isEmpty());
        }
    }
}
