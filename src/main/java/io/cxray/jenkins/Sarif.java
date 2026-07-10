package io.cxray.jenkins;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import hudson.FilePath;
import io.cxray.jenkins.local.Compliance;
import io.cxray.jenkins.local.Finding;
import io.cxray.jenkins.local.GateResult;
import java.io.IOException;
import java.io.PrintStream;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Emits findings as <a href="https://sarifweb.azurewebsites.net/">SARIF 2.1.0</a> — the standard
 * static-analysis interchange format that GitHub code scanning, Azure DevOps, and many IDEs ingest.
 * Each finding carries its CXRay severity plus the framework mapping and remediation (from
 * {@link Compliance}) in {@code properties}, so the auditor-facing mapping travels with the results.
 */
public final class Sarif {

    private Sarif() {}

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Build the SARIF 2.1.0 document (pure — unit-testable without a workspace). */
    public static String build(GateResult result, String mode, String target, String toolVersion) {
        ObjectNode root = MAPPER.createObjectNode();
        root.put("$schema", "https://json.schemastore.org/sarif-2.1.0.json");
        root.put("version", "2.1.0");
        ArrayNode runs = root.putArray("runs");
        ObjectNode run = runs.addObject();

        ObjectNode driver = run.putObject("tool").putObject("driver");
        driver.put("name", "CXRay Security Gate");
        driver.put("informationUri", "https://github.com/fankh/cxray-jenkins");
        driver.put("version", toolVersion == null || toolVersion.isEmpty() ? "1.0.0" : toolVersion);
        ArrayNode rules = driver.putArray("rules");
        Set<String> seenRules = new LinkedHashSet<>();
        for (Finding f : result.findings) {
            if (seenRules.add(f.check)) {
                ObjectNode rule = rules.addObject();
                rule.put("id", f.check);
                rule.put("name", f.check);
                rule.putObject("shortDescription").put("text", "CXRay " + f.check + " check");
            }
        }

        ArrayNode results = run.putArray("results");
        for (Finding f : result.findings) {
            ObjectNode r = results.addObject();
            r.put("ruleId", f.check);
            r.put("level", level(f.severity));
            r.putObject("message").put("text",
                    f.title + (f.detail == null || f.detail.isEmpty() ? "" : " — " + f.detail));
            ObjectNode props = r.putObject("properties");
            props.put("severity", f.severity == null ? "" : f.severity);
            props.put("frameworks", Compliance.frameworks(f.check, f.title));
            props.put("remediation", Compliance.remediation(f.check, f.title));
        }

        ObjectNode runProps = run.putObject("properties");
        runProps.put("verdict", result.verdict);
        runProps.put("mode", mode == null ? "" : mode);
        runProps.put("target", target == null ? "" : target);

        try {
            return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(root);
        } catch (IOException e) {
            return root.toString();
        }
    }

    /** Build the SARIF document and write it to {@code path} in the workspace. */
    public static void emit(FilePath workspace, String path, GateResult result, String mode, String target,
                            String toolVersion, PrintStream log) throws IOException, InterruptedException {
        workspace.child(path).write(build(result, mode, target, toolVersion), "UTF-8");
        log.println("[CXRay] Wrote SARIF to " + path + " (SARIF 2.1.0; upload to GitHub code scanning or archive).");
    }

    /** SARIF severity levels: error / warning / note. */
    private static String level(String severity) {
        String s = severity == null ? "" : severity.toLowerCase();
        if ("critical".equals(s) || "high".equals(s)) return "error";
        if ("medium".equals(s) || "review".equals(s)) return "warning";
        return "note";
    }
}
