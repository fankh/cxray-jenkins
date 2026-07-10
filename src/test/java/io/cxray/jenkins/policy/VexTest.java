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
import java.util.Arrays;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class VexTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private final PrintStream log = new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8);

    private FilePath workspaceWith(String vexJson) throws Exception {
        File ws = tmp.newFolder("ws");
        File dir = new File(ws, ".cxray");
        if (!dir.mkdirs()) throw new IllegalStateException("mkdir failed");
        new FilePath(new File(dir, "vex.json")).write(vexJson, "UTF-8");
        return new FilePath(ws);
    }

    @Test
    public void absentVexIsNull() throws Exception {
        assertNull(Vex.load(new FilePath(tmp.newFolder("empty")), log));
    }

    @Test
    public void suppressesNotAffectedAndFixed_recomputesVerdict() throws Exception {
        Vex v = Vex.load(workspaceWith("{\"@context\":\"https://openvex.dev/ns/v0.2.0\",\"statements\":["
                + "{\"vulnerability\":{\"name\":\"CVE-2024-0001\"},\"status\":\"not_affected\"},"
                + "{\"vulnerability\":\"CVE-2024-0002\",\"status\":\"fixed\"}]}"), log);
        GateResult r = new GateResult("fail", Arrays.asList(
                new Finding("cve", "critical", "CVE-2024-0001", "base 9.8", 0),   // suppressed
                new Finding("cve", "critical", "CVE-2024-0002", "base 9.1", 0)));  // suppressed
        GateResult out = v.apply(r, log);
        assertEquals("pass", out.verdict);
        assertEquals(0, out.findings.size());
    }

    @Test
    public void keepsAffectedAndUnknown() throws Exception {
        Vex v = Vex.load(workspaceWith("{\"statements\":["
                + "{\"vulnerability\":\"CVE-2024-0001\",\"status\":\"not_affected\"},"
                + "{\"vulnerability\":\"CVE-2024-0009\",\"status\":\"affected\"}]}"), log);
        GateResult r = new GateResult("fail", Arrays.asList(
                new Finding("cve", "critical", "CVE-2024-0001", "base 9.8", 0),   // suppressed
                new Finding("cve", "critical", "CVE-2024-0009", "base 9.0", 0)));  // affected → kept
        GateResult out = v.apply(r, log);
        assertEquals("fail", out.verdict);
        assertEquals(1, out.findings.size());
        assertEquals("CVE-2024-0009", out.findings.get(0).title);
    }
}
