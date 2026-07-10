package io.cxray.jenkins.policy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import hudson.FilePath;
import io.cxray.jenkins.local.Finding;
import io.cxray.jenkins.local.GateResult;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.Collections;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class PolicyTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private final PrintStream log = new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8);

    private FilePath workspaceWith(String policyJson) throws Exception {
        File ws = tmp.newFolder("ws");
        File dir = new File(ws, ".cxray");
        if (!dir.mkdirs()) throw new IllegalStateException("mkdir failed");
        new FilePath(new File(dir, "policy.json")).write(policyJson, "UTF-8");
        return new FilePath(ws);
    }

    @Test
    public void absentPolicyIsNull() throws Exception {
        FilePath ws = new FilePath(tmp.newFolder("empty"));
        assertNull(Policy.load(ws, log));
    }

    @Test
    public void parsesConfigOverrides() throws Exception {
        Policy p = Policy.load(workspaceWith(
                "{\"failOn\":\"review\",\"gates\":[\"CVE\",\"ai\"],\"maxCvss\":7.5,\"failOnKev\":false}"), log);
        assertEquals("review", p.getFailOn());
        assertEquals(Arrays.asList("cve", "ai"), p.getGates()); // normalized lowercase
        assertEquals(Double.valueOf(7.5), p.getMaxCvss());
        assertEquals(Boolean.FALSE, p.getFailOnKev());
    }

    @Test
    public void unexpiredWaiverSuppressesFindingAndRecomputesVerdict() throws Exception {
        Policy p = Policy.load(workspaceWith(
                "{\"waivers\":[{\"check\":\"cve\",\"id\":\"CVE-2024-0001\",\"expires\":\"2999-01-01\"}]}"), log);
        GateResult r = new GateResult("fail", Collections.singletonList(
                new Finding("cve", "critical", "CVE-2024-0001", "base 9.8", 0)));
        GateResult out = p.applyWaivers(r, log, LocalDate.of(2026, 7, 10));
        assertEquals("pass", out.verdict);   // the only finding was waived
        assertEquals(0, out.findings.size());
    }

    @Test
    public void expiredWaiverDoesNotSuppress() throws Exception {
        Policy p = Policy.load(workspaceWith(
                "{\"waivers\":[{\"check\":\"cve\",\"id\":\"CVE-2024-0001\",\"expires\":\"2020-01-01\"}]}"), log);
        GateResult r = new GateResult("fail", Collections.singletonList(
                new Finding("cve", "critical", "CVE-2024-0001", "base 9.8", 0)));
        GateResult out = p.applyWaivers(r, log, LocalDate.of(2026, 7, 10));
        assertEquals("fail", out.verdict);   // waiver expired → finding stays
        assertEquals(1, out.findings.size());
    }

    @Test
    public void waiverLeavesUnmatchedFindingsAndRecomputes() throws Exception {
        Policy p = Policy.load(workspaceWith(
                "{\"waivers\":[{\"check\":\"cve\",\"id\":\"CVE-2024-0001\"}]}"), log);
        GateResult r = new GateResult("fail", Arrays.asList(
                new Finding("cve", "critical", "CVE-2024-0001", "base 9.8", 0),   // waived
                new Finding("license", "medium", "LGPL-3.0", "review", 0)));       // stays
        GateResult out = p.applyWaivers(r, log, LocalDate.of(2026, 7, 10));
        assertEquals("review", out.verdict); // only the medium license finding remains
        assertEquals(1, out.findings.size());
    }
}
