package io.cxray.jenkins;

import hudson.model.Run;
import io.cxray.jenkins.local.Compliance;
import io.cxray.jenkins.local.Finding;
import java.util.Collections;
import java.util.List;
import jenkins.model.RunAction2;

/**
 * Persisted per-build report — renders the "CXRay Report" tab (index.jelly) and a build-page
 * summary (summary.jelly). Styling follows the CXRay console convention: severity/verdict as bold
 * UPPERCASE colored text using the exact design tokens (never generic pill badges).
 */
public class CXRayReportAction implements RunAction2 {

    private final String verdict;   // pass | review | fail
    private final String mode;      // local | api
    private final String target;    // e.g. "image <id>" or "mcp/server.json, Modelfile"
    private final List<Finding> findings;
    private final long generatedAt;

    private transient Run<?, ?> run;

    public CXRayReportAction(String verdict, String mode, String target, List<Finding> findings, long generatedAt) {
        this.verdict = verdict;
        this.mode = mode;
        this.target = target;
        this.findings = findings;
        this.generatedAt = generatedAt;
    }

    // ── Action ──
    @Override
    public String getIconFileName() {
        return "document.png";
    }

    @Override
    public String getDisplayName() {
        return "CXRay Report";
    }

    @Override
    public String getUrlName() {
        return "cxray";
    }

    @Override
    public void onAttached(Run<?, ?> r) { this.run = r; }

    @Override
    public void onLoad(Run<?, ?> r) { this.run = r; }

    // ── view helpers ──
    public Run<?, ?> getRun() { return run; }
    public String getVerdict() { return verdict; }
    public String getMode() { return mode; }
    public String getTarget() { return target; }
    public List<Finding> getFindings() { return findings == null ? Collections.emptyList() : findings; }
    public int getFindingCount() { return getFindings().size(); }
    public String getGeneratedAt() { return new java.util.Date(generatedAt).toString(); }

    /** exact CXRay design tokens (design-tokens.css) for severity / verdict text. */
    public String color(String s) {
        if (s == null) return "#6B717D";
        switch (s.toLowerCase()) {
            case "critical":
            case "fail":
                return "#F0616D";
            case "high":
                return "#FF9D40";
            case "medium":
            case "review":
                return "#FFD446";
            case "low":
            case "pass":
                return "#52C41A";
            default:
                return "#6B717D";
        }
    }

    public String getVerdictColor() { return color(verdict); }

    /** Framework references a finding evidences (OWASP LLM / ASI / ATLAS) — for the report view. */
    public String frameworks(Finding f) { return Compliance.frameworks(f.check, f.title); }

    /** Concrete fix for a finding — for the report view. */
    public String remediation(Finding f) { return Compliance.remediation(f.check, f.title); }
}
