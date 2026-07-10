package io.cxray.jenkins.local;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.List;
import org.junit.Test;

public class PrioritizerTest {

    @Test
    public void kevFirstThenSeverityThenCvss() {
        List<Finding> in = Arrays.asList(
                new Finding("license", "medium", "GPL-3.0", "deny", 0),
                new Finding("cve", "critical", "CVE-A", "base 9.1", 0),
                new Finding("cve", "critical", "CVE-KEV", "base 7.5 · KEV", 0), // KEV, lower CVSS
                new Finding("secrets", "high", "aws-key", ".env", 0));
        List<Finding> out = Prioritizer.byExploitability(in);
        assertEquals("CVE-KEV", out.get(0).title);   // KEV wins even at lower CVSS
        assertEquals("CVE-A", out.get(1).title);      // then critical by CVSS
        assertEquals("aws-key", out.get(2).title);    // then high
        assertEquals("GPL-3.0", out.get(3).title);    // then medium
    }

    @Test
    public void higherCvssFirstWithinSameSeverity() {
        List<Finding> in = Arrays.asList(
                new Finding("cve", "critical", "low-base", "base 9.0", 0),
                new Finding("cve", "critical", "high-base", "base 9.9", 0));
        List<Finding> out = Prioritizer.byExploitability(in);
        assertEquals("high-base", out.get(0).title);
    }

    @Test
    public void doesNotMutateInputOrDropFindings() {
        List<Finding> in = Arrays.asList(
                new Finding("cve", "low", "a", "base 2.0", 0),
                new Finding("cve", "critical", "b", "base 9.0", 0));
        List<Finding> out = Prioritizer.byExploitability(in);
        assertEquals(2, out.size());
        assertEquals("a", in.get(0).title); // input order preserved
    }
}
