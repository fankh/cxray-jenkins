package io.cxray.jenkins.policy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import hudson.FilePath;
import io.cxray.jenkins.local.Finding;
import io.cxray.jenkins.local.GateResult;
import java.io.IOException;
import java.io.PrintStream;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;

/**
 * Repo-committed gate policy — {@code .cxray/policy.json} in the workspace — so gate configuration
 * lives with the code it gates (policy-as-code). Any field present overrides the job config;
 * absent fields fall back to it. Shares the same shape the {@code cxray-gate} CLI reads, so a repo's
 * policy is honored identically in Jenkins and in the GitHub Action.
 *
 * <pre>
 * {
 *   "failOn": "fail",                     // or "review"
 *   "gates": ["cve","license","secrets","ai"],
 *   "maxCvss": 9.0,
 *   "failOnKev": true,
 *   "waivers": [
 *     {"check":"cve","id":"CVE-2024-0001","reason":"not reachable","expires":"2026-12-31"}
 *   ]
 * }
 * </pre>
 */
public final class Policy {

    /** Workspace-relative location of the policy file. */
    public static final String PATH = ".cxray/policy.json";

    private String failOn;
    private List<String> gates;
    private Double maxCvss;
    private Boolean failOnKev;
    private Boolean dryRun;
    private final List<Waiver> waivers = new ArrayList<>();

    public String getFailOn() { return failOn; }
    public List<String> getGates() { return gates; }
    public Double getMaxCvss() { return maxCvss; }
    public Boolean getFailOnKev() { return failOnKev; }
    public Boolean getDryRun() { return dryRun; }
    public List<Waiver> getWaivers() { return waivers; }

    /** A time-boxed, owned exception that suppresses a matching finding. */
    public static final class Waiver {
        public String check;
        public String id;
        public String reason;
        public String expires; // yyyy-MM-dd; empty/absent = no expiry
    }

    /** Load {@code .cxray/policy.json} from the workspace; {@code null} when absent or unparseable. */
    public static Policy load(FilePath workspace, PrintStream log) throws IOException, InterruptedException {
        if (workspace == null) return null;
        FilePath fp = workspace.child(PATH);
        if (!fp.exists()) return null;
        try {
            Policy p = populate(new ObjectMapper().readTree(fp.readToString()));
            log.println("[CXRay] Loaded policy from " + PATH
                    + (p.waivers.isEmpty() ? "" : " (" + p.waivers.size() + " waiver(s))"));
            return p;
        } catch (IOException e) {
            log.println("[CXRay] WARNING: could not parse " + PATH + " — ignoring (" + e.getMessage() + ")");
            return null;
        }
    }

    /** Parse a policy from a JSON string — used for the admin-set org default (global config). */
    public static Policy fromJson(String json, PrintStream log) {
        if (json == null || json.trim().isEmpty()) return null;
        try {
            Policy p = populate(new ObjectMapper().readTree(json));
            log.println("[CXRay] Applied org default policy from global config"
                    + (p.waivers.isEmpty() ? "" : " (" + p.waivers.size() + " waiver(s))"));
            return p;
        } catch (IOException e) {
            log.println("[CXRay] WARNING: could not parse the org default policy — ignoring (" + e.getMessage() + ")");
            return null;
        }
    }

    /**
     * Layer {@code override} on top of {@code base} (policy inheritance: org default → repo). A scalar
     * set in {@code override} wins; otherwise {@code base} fills it. Waivers are the union of both.
     */
    public static Policy layered(Policy base, Policy override) {
        if (base == null) return override;
        if (override == null) return base;
        Policy p = new Policy();
        p.failOn = override.failOn != null ? override.failOn : base.failOn;
        p.gates = override.gates != null ? override.gates : base.gates;
        p.maxCvss = override.maxCvss != null ? override.maxCvss : base.maxCvss;
        p.failOnKev = override.failOnKev != null ? override.failOnKev : base.failOnKev;
        p.dryRun = override.dryRun != null ? override.dryRun : base.dryRun;
        p.waivers.addAll(base.waivers);
        p.waivers.addAll(override.waivers);
        return p;
    }

    private static Policy populate(JsonNode n) {
        Policy p = new Policy();
        if (n.hasNonNull("failOn")) p.failOn = n.get("failOn").asText();
        if (n.has("gates") && n.get("gates").isArray()) {
            p.gates = new ArrayList<>();
            for (JsonNode g : n.get("gates")) {
                String v = g.asText().trim().toLowerCase();
                if (!v.isEmpty()) p.gates.add(v);
            }
        }
        if (n.hasNonNull("maxCvss")) p.maxCvss = n.get("maxCvss").asDouble();
        if (n.hasNonNull("failOnKev")) p.failOnKev = n.get("failOnKev").asBoolean();
        if (n.hasNonNull("dryRun")) p.dryRun = n.get("dryRun").asBoolean();
        if (n.has("waivers") && n.get("waivers").isArray()) {
            for (JsonNode w : n.get("waivers")) {
                Waiver wv = new Waiver();
                wv.check = txt(w, "check");
                wv.id = txt(w, "id");
                wv.reason = txt(w, "reason");
                wv.expires = txt(w, "expires");
                p.waivers.add(wv);
            }
        }
        return p;
    }

    /**
     * Suppress findings matched by an unexpired waiver and recompute the verdict from what remains.
     * When no waiver matches, the original result is returned unchanged (no behavior drift).
     */
    public GateResult applyWaivers(GateResult r, PrintStream log, LocalDate today) {
        if (waivers.isEmpty() || r.findings.isEmpty()) return r;
        List<Finding> kept = new ArrayList<>();
        int waived = 0;
        for (Finding f : r.findings) {
            Waiver w = matchedBy(f, today);
            if (w != null) {
                waived++;
                log.println("  [CXRay] waived: " + f.check + " · " + f.title
                        + (w.reason != null && !w.reason.isEmpty() ? " — " + w.reason : ""));
            } else {
                kept.add(f);
            }
        }
        if (waived == 0) return r;
        log.println("[CXRay] " + waived + " finding(s) waived by policy; verdict recomputed from remainder.");
        return new GateResult(severityVerdict(kept), kept);
    }

    private Waiver matchedBy(Finding f, LocalDate today) {
        for (Waiver w : waivers) {
            if (w.check != null && !w.check.isEmpty() && !w.check.equalsIgnoreCase(f.check)) continue;
            if (w.id != null && !w.id.isEmpty()
                    && !w.id.equalsIgnoreCase(f.title)
                    && (f.detail == null || !f.detail.contains(w.id))) continue;
            if (expired(w.expires, today)) continue;
            return w;
        }
        return null;
    }

    private static boolean expired(String expires, LocalDate today) {
        if (expires == null || expires.trim().isEmpty()) return false; // no expiry = always valid
        try {
            return LocalDate.parse(expires.trim()).isBefore(today);
        } catch (DateTimeParseException e) {
            return false; // unparseable date → don't treat as expired (lenient, logged elsewhere)
        }
    }

    /** Conservative verdict from the surviving findings — applied only when waivers changed the set. */
    private static String severityVerdict(List<Finding> findings) {
        String v = "pass";
        for (Finding f : findings) {
            String s = f.severity == null ? "" : f.severity.toLowerCase();
            if ("critical".equals(s) || "high".equals(s)) return "fail";
            if ("medium".equals(s)) v = "review";
        }
        return v;
    }

    private static String txt(JsonNode n, String field) {
        JsonNode v = n.get(field);
        return v == null || v.isNull() ? null : v.asText();
    }
}
