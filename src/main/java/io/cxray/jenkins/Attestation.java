package io.cxray.jenkins;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import hudson.FilePath;
import io.cxray.jenkins.local.Finding;
import io.cxray.jenkins.local.GateResult;
import io.cxray.jenkins.policy.Policy;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.List;

/**
 * Emits an <a href="https://in-toto.io/Statement/v1">in-toto Statement</a> (SLSA-style) recording
 * the gate verdict and its inputs — a portable, machine-readable attestation that a build met (or
 * failed) CXRay policy. Left <em>unsigned</em> on purpose: sign the emitted statement with
 * cosign/in-toto as a separate CI step (the standard split). Includes a digest of the policy file
 * so the attestation is bound to the exact policy that produced it.
 */
public final class Attestation {

    private Attestation() {}

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Build the in-toto Statement JSON (pure — unit-testable without a workspace). */
    public static String build(GateResult result, String mode, String target, String policyDigest,
                               String buildJob, int buildNumber, String buildUrl, long generatedAt) {
        int crit = 0, high = 0, med = 0, low = 0;
        for (Finding f : result.findings) {
            String s = f.severity == null ? "" : f.severity.toLowerCase();
            switch (s) {
                case "critical": crit++; break;
                case "high": high++; break;
                case "medium": med++; break;
                case "low": low++; break;
                default: break;
            }
        }

        ObjectNode stmt = MAPPER.createObjectNode();
        stmt.put("_type", "https://in-toto.io/Statement/v1");
        stmt.put("predicateType", "https://cxray.io/attestations/gate/v1");

        ArrayNode subject = stmt.putArray("subject");
        ObjectNode subj = subject.addObject();
        subj.put("name", target == null ? "workspace" : target);

        ObjectNode pred = stmt.putObject("predicate");
        pred.put("verdict", result.verdict);
        pred.put("blocked", "fail".equals(result.verdict));
        pred.put("mode", mode);
        pred.put("findingCount", result.findings.size());
        ObjectNode sev = pred.putObject("severities");
        sev.put("critical", crit);
        sev.put("high", high);
        sev.put("medium", med);
        sev.put("low", low);
        if (policyDigest != null) pred.put("policyDigest", policyDigest);
        else pred.putNull("policyDigest");
        pred.put("generatedAt", Instant.ofEpochMilli(generatedAt).toString());
        ObjectNode inv = pred.putObject("invocation");
        inv.put("job", buildJob == null ? "" : buildJob);
        inv.put("buildNumber", buildNumber);
        if (buildUrl != null) inv.put("buildUrl", buildUrl);

        try {
            return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(stmt);
        } catch (IOException e) {
            return stmt.toString(); // pretty-printer never fails on a plain tree; fall back defensively
        }
    }

    /** Build the statement and write it to {@code path} in the workspace. */
    public static void emit(FilePath workspace, String path, GateResult result, String mode, String target,
                            String buildJob, int buildNumber, String buildUrl, long generatedAt, PrintStream log)
            throws IOException, InterruptedException {
        String policyDigest = digestOf(workspace, Policy.PATH);
        String json = build(result, mode, target, policyDigest, buildJob, buildNumber, buildUrl, generatedAt);
        workspace.child(path).write(json, "UTF-8");
        log.println("[CXRay] Wrote gate attestation to " + path
                + " (in-toto Statement; sign with cosign/in-toto in a later step).");
    }

    /** {@code sha256:<hex>} of a workspace file, or {@code null} when it's absent/unreadable. */
    private static String digestOf(FilePath workspace, String rel) throws InterruptedException {
        try {
            FilePath fp = workspace.child(rel);
            if (!fp.exists()) return null;
            byte[] bytes = fp.readToString().getBytes(StandardCharsets.UTF_8);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(bytes);
            StringBuilder sb = new StringBuilder("sha256:");
            for (byte b : d) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (IOException | NoSuchAlgorithmException e) {
            return null;
        }
    }
}
