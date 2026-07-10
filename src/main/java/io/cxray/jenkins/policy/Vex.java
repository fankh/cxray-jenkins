package io.cxray.jenkins.policy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import hudson.FilePath;
import io.cxray.jenkins.local.Finding;
import io.cxray.jenkins.local.GateResult;
import java.io.IOException;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * VEX (Vulnerability Exploitability eXchange) suppression — reads {@code .cxray/vex.json} in the
 * OpenVEX shape and drops CVE findings whose exploitability status is {@code not_affected} or
 * {@code fixed}. This is the standard, tool-neutral way to silence non-exploitable CVEs (vs. a
 * hand-maintained waiver): the same VEX document a repo ships is honored by the gate.
 *
 * <pre>
 * { "@context": "https://openvex.dev/ns/v0.2.0",
 *   "statements": [
 *     { "vulnerability": {"name": "CVE-2024-0001"}, "status": "not_affected", "justification": "…" },
 *     { "vulnerability": "CVE-2024-0002", "status": "fixed" }
 *   ] }
 * </pre>
 */
public final class Vex {

    /** Workspace-relative location of the VEX document. */
    public static final String PATH = ".cxray/vex.json";

    private final Set<String> suppressed = new LinkedHashSet<>(); // CVE ids marked not_affected/fixed

    public Set<String> suppressed() {
        return suppressed;
    }

    /** Load {@code .cxray/vex.json}; {@code null} when absent or unparseable. */
    public static Vex load(FilePath workspace, PrintStream log) throws IOException, InterruptedException {
        if (workspace == null) return null;
        FilePath fp = workspace.child(PATH);
        if (!fp.exists()) return null;
        try {
            JsonNode root = new ObjectMapper().readTree(fp.readToString());
            JsonNode statements = root.get("statements");
            if (statements == null || !statements.isArray()) return null;
            Vex v = new Vex();
            for (JsonNode s : statements) {
                String status = text(s.get("status"));
                if (!"not_affected".equalsIgnoreCase(status) && !"fixed".equalsIgnoreCase(status)) continue;
                String id = vulnId(s.get("vulnerability"));
                if (id != null && !id.isEmpty()) v.suppressed.add(id.toUpperCase());
            }
            log.println("[CXRay] Loaded VEX from " + PATH + " (" + v.suppressed.size() + " non-exploitable CVE(s))");
            return v;
        } catch (IOException e) {
            log.println("[CXRay] WARNING: could not parse " + PATH + " — ignoring (" + e.getMessage() + ")");
            return null;
        }
    }

    /** Drop CVE findings marked non-exploitable by VEX; recompute the verdict from what remains. */
    public GateResult apply(GateResult r, PrintStream log) {
        if (suppressed.isEmpty() || r.findings.isEmpty()) return r;
        List<Finding> kept = new ArrayList<>();
        int dropped = 0;
        for (Finding f : r.findings) {
            if ("cve".equalsIgnoreCase(f.check) && f.title != null && suppressed.contains(f.title.toUpperCase())) {
                dropped++;
                log.println("  [CXRay] VEX-suppressed (non-exploitable): " + f.title);
            } else {
                kept.add(f);
            }
        }
        if (dropped == 0) return r;
        log.println("[CXRay] " + dropped + " CVE finding(s) suppressed by VEX; verdict recomputed.");
        return new GateResult(severityVerdict(kept), kept);
    }

    private static String vulnId(JsonNode vuln) {
        if (vuln == null || vuln.isNull()) return null;
        if (vuln.isTextual()) return vuln.asText();
        String name = text(vuln.get("name"));
        if (name != null) return name;
        return text(vuln.get("@id"));
    }

    private static String severityVerdict(List<Finding> findings) {
        String v = "pass";
        for (Finding f : findings) {
            String s = f.severity == null ? "" : f.severity.toLowerCase();
            if ("critical".equals(s) || "high".equals(s)) return "fail";
            if ("medium".equals(s)) v = "review";
        }
        return v;
    }

    private static String text(JsonNode n) {
        return n == null || n.isNull() ? null : n.asText();
    }
}
