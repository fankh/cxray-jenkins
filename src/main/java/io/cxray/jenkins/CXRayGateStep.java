package io.cxray.jenkins;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import hudson.AbortException;
import hudson.EnvVars;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractProject;
import hudson.model.Item;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.security.ACL;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import io.cxray.jenkins.api.CxrayClient;
import io.cxray.jenkins.local.Finding;
import io.cxray.jenkins.local.GateResult;
import io.cxray.jenkins.local.LocalAnalyzers;
import io.cxray.jenkins.policy.Policy;
import java.io.IOException;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildStep;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

/**
 * CXRay Security Gate — two methods, selected by {@link #mode}:
 * <ul>
 *   <li><b>local</b> — offline agent/AI-security analysis of workspace files (no server, no creds).</li>
 *   <li><b>api</b> — gate an image already scanned in CXRay via the API (scan-and-gate loop is P3).</li>
 * </ul>
 * Fails the build when the worst verdict is {@code fail} (or {@code review} when {@code failOn=review}).
 * A misconfiguration reports a distinct ERROR (not a security FAILURE).
 */
public class CXRayGateStep extends Builder implements SimpleBuildStep {

    private String mode = "local";
    private String failOn = "fail";

    // --- local mode ---
    private String configPath;
    private String manifestPath;
    private String modelFilePath;

    // --- api mode ---
    private String imageId;
    private String credentialsId;
    private String gates = "cve,license,secrets,ai";
    private double maxCvss = 9.0;
    private boolean failOnKev = true;

    // --- api mode: scan-and-gate (P3) — set instead of imageId to scan a registry image first ---
    private String repo;
    private String image;
    private String tag = "latest";
    private String registryCredentialsId;
    private int pollTimeoutSec = 600;
    private int pollIntervalSec = 10;

    @DataBoundConstructor
    public CXRayGateStep() {
    }

    public String getMode() { return mode; }
    @DataBoundSetter public void setMode(String mode) { this.mode = "api".equals(mode) ? "api" : "local"; }

    public String getFailOn() { return failOn; }
    @DataBoundSetter public void setFailOn(String failOn) { this.failOn = "review".equals(failOn) ? "review" : "fail"; }

    public String getConfigPath() { return configPath; }
    @DataBoundSetter public void setConfigPath(String v) { this.configPath = fix(v); }
    public String getManifestPath() { return manifestPath; }
    @DataBoundSetter public void setManifestPath(String v) { this.manifestPath = fix(v); }
    public String getModelFilePath() { return modelFilePath; }
    @DataBoundSetter public void setModelFilePath(String v) { this.modelFilePath = fix(v); }

    public String getImageId() { return imageId; }
    @DataBoundSetter public void setImageId(String v) { this.imageId = fix(v); }
    public String getCredentialsId() { return credentialsId; }
    @DataBoundSetter public void setCredentialsId(String v) { this.credentialsId = fix(v); }
    public String getGates() { return gates; }
    @DataBoundSetter public void setGates(String v) { this.gates = (v == null || v.trim().isEmpty()) ? "cve,license,secrets,ai" : v.trim(); }
    public double getMaxCvss() { return maxCvss; }
    @DataBoundSetter public void setMaxCvss(double v) { this.maxCvss = v; }
    public boolean isFailOnKev() { return failOnKev; }
    @DataBoundSetter public void setFailOnKev(boolean v) { this.failOnKev = v; }
    public String getRepo() { return repo; }
    @DataBoundSetter public void setRepo(String v) { this.repo = fix(v); }
    public String getImage() { return image; }
    @DataBoundSetter public void setImage(String v) { this.image = fix(v); }
    public String getTag() { return tag; }
    @DataBoundSetter public void setTag(String v) { this.tag = (v == null || v.trim().isEmpty()) ? "latest" : v.trim(); }
    public String getRegistryCredentialsId() { return registryCredentialsId; }
    @DataBoundSetter public void setRegistryCredentialsId(String v) { this.registryCredentialsId = fix(v); }
    public int getPollTimeoutSec() { return pollTimeoutSec; }
    @DataBoundSetter public void setPollTimeoutSec(int v) { this.pollTimeoutSec = v > 0 ? v : 600; }
    public int getPollIntervalSec() { return pollIntervalSec; }
    @DataBoundSetter public void setPollIntervalSec(int v) { this.pollIntervalSec = v >= 2 ? v : 10; }

    private static String fix(String s) {
        return (s == null || s.trim().isEmpty()) ? null : s.trim();
    }

    @Override
    public void perform(Run<?, ?> run, FilePath workspace, EnvVars env,
                        Launcher launcher, TaskListener listener)
            throws InterruptedException, IOException {
        PrintStream log = listener.getLogger();
        Policy policy = Policy.load(workspace, log);
        GateResult result = "api".equals(mode) ? performApi(run, workspace, log, policy) : performLocal(workspace, log);
        if (policy != null) {
            result = policy.applyWaivers(result, log, java.time.LocalDate.now());
        }

        String target = "api".equals(mode)
                ? (imageId != null ? ("image " + imageId)
                        : ((repo == null ? "" : repo + "/") + image + ":" + (tag == null ? "latest" : tag)))
                : localTarget();
        run.addAction(new CXRayReportAction(result.verdict, mode, target, result.findings, System.currentTimeMillis()));

        for (Finding f : result.findings) {
            log.println(String.format("  [%s] %-8s %s — %s%s",
                    f.check, f.severity.toUpperCase(), f.title, f.detail,
                    f.line > 0 ? " (line " + f.line + ")" : ""));
        }
        log.println("[CXRay] Verdict: " + result.verdict.toUpperCase()
                + " (" + result.findings.size() + " finding" + (result.findings.size() == 1 ? "" : "s") + ")");

        // Surface the verdict on the build page so a blocked build shows *why* at a glance.
        run.setDescription(describe(result));

        String effFailOn = (policy != null && policy.getFailOn() != null) ? policy.getFailOn()
                : (failOn == null ? "fail" : failOn);
        boolean block = "fail".equals(result.verdict)
                || ("review".equals(result.verdict) && "review".equals(effFailOn));
        if (block) {
            CXRayGlobalConfiguration gc = CXRayGlobalConfiguration.get();
            if (gc != null && gc.getNotifyWebhookUrl() != null) {
                String root = Jenkins.get().getRootUrl();
                String buildUrl = root != null ? root + run.getUrl() : null;
                Notifier.gateFailed(gc.getNotifyWebhookUrl(), result.verdict, mode, target,
                        result.findings.size(), buildUrl, gc.getTimeoutSec(), log);
            }
            throw new AbortException("[CXRay] Gate " + result.verdict.toUpperCase()
                    + " — failing the build (fail-on=" + effFailOn + ").");
        }
        log.println("[CXRay] Gate passed.");
    }

    // ── Method B: local/offline ──
    private GateResult performLocal(FilePath workspace, PrintStream log) throws InterruptedException, IOException {
        log.println("[CXRay] Local (offline) agent-security gate");
        String config = read(workspace, configPath, log);
        String manifest = read(workspace, manifestPath, log);
        String model = read(workspace, modelFilePath, log);
        if (config == null && manifest == null && model == null) {
            throw new AbortException("[CXRay] No inputs — set at least one of configPath / manifestPath / modelFilePath.");
        }
        return LocalAnalyzers.run(config, manifest, model);
    }

    // ── Method A: CXRay API (scan-and-gate, or gate an already-scanned image) ──
    private GateResult performApi(Run<?, ?> run, FilePath workspace, PrintStream log, Policy policy) throws AbortException, InterruptedException, IOException {
        // API URL is admin-controlled (global config only) — a per-job override would let a job
        // configurer redirect the access-key bearer to an attacker host (SSRF credential exfil).
        CXRayGlobalConfiguration cfg = CXRayGlobalConfiguration.get();
        String base = cfg != null ? cfg.getApiUrl() : null;
        if (base == null || base.isEmpty()) throw new AbortException("[CXRay] No API URL — an admin must set it in Manage Jenkins → System.");
        if (credentialsId == null) throw new AbortException("[CXRay] API mode needs CXRay access-key credentials.");
        StandardUsernamePasswordCredentials c = CredentialsProvider.findCredentialById(
                credentialsId, StandardUsernamePasswordCredentials.class, run, Collections.emptyList());
        if (c == null) throw new AbortException("[CXRay] Credentials not found: " + credentialsId);

        CxrayClient client = new CxrayClient(base, c.getUsername(), c.getPassword().getPlainText(), cfg.getTimeoutSec());

        // Policy-as-code overrides job config when present.
        List<String> want = new ArrayList<>();
        if (policy != null && policy.getGates() != null) {
            want.addAll(policy.getGates());
        } else {
            for (String g : gates.split(",")) { g = g.trim().toLowerCase(); if (!g.isEmpty()) want.add(g); }
        }
        double effMaxCvss = (policy != null && policy.getMaxCvss() != null) ? policy.getMaxCvss() : maxCvss;
        boolean effFailOnKev = (policy != null && policy.getFailOnKev() != null) ? policy.getFailOnKev() : failOnKev;

        try {
            String id = imageId;
            if (id == null && image != null) {
                // scan-and-gate: pull + scan the registry image, then poll to completion
                String regUser = null, regPass = null;
                if (registryCredentialsId != null) {
                    StandardUsernamePasswordCredentials rc = CredentialsProvider.findCredentialById(
                            registryCredentialsId, StandardUsernamePasswordCredentials.class, run, Collections.emptyList());
                    if (rc != null) { regUser = rc.getUsername(); regPass = rc.getPassword().getPlainText(); }
                }
                String ref = (repo == null ? "" : repo + "/") + image + ":" + (tag == null ? "latest" : tag);
                log.println("[CXRay] Scanning " + ref);
                id = client.startScan(repo, image, tag, regUser, regPass);
                log.println("[CXRay] Scan started — image " + id + "; polling (timeout " + pollTimeoutSec + "s, every " + pollIntervalSec + "s)…");
                long deadline = System.currentTimeMillis() + pollTimeoutSec * 1000L;
                while (client.isAnalyzing(id)) {
                    if (System.currentTimeMillis() > deadline) {
                        throw new AbortException("[CXRay] Scan timed out after " + pollTimeoutSec + "s (image " + id + ").");
                    }
                    Thread.sleep(pollIntervalSec * 1000L);
                    log.println("[CXRay] …analyzing " + id);
                }
                log.println("[CXRay] Scan complete.");
            }
            if (id == null) throw new AbortException("[CXRay] API mode needs an Image ID, or repo/image/tag to scan.");

            log.println("[CXRay] Gating image " + id + " (" + base + ")");
            List<Finding> all = new ArrayList<>();
            String verdict = "pass";
            if (want.contains("cve")) verdict = merge(verdict, all, "CVE/KEV", client.cveGate(id, effMaxCvss, effFailOnKev), log);
            if (want.contains("license")) verdict = merge(verdict, all, "License", client.licenseGate(id), log);
            if (want.contains("secrets")) verdict = merge(verdict, all, "Secrets", client.secretsGate(id), log);
            if (want.contains("ai")) verdict = merge(verdict, all, "AI supply-chain", client.aiGate(id), log);
            if (want.contains("mcp")) {
                String manifest = read(workspace, manifestPath, log);
                if (manifest == null) {
                    log.println("  MCP: skipped — no manifestPath to gate (set manifestPath to a tools/list manifest).");
                } else {
                    String serverId = image != null ? image : (imageId != null ? imageId : "jenkins");
                    verdict = merge(verdict, all, "MCP (OWASP-Agentic)",
                            client.mcpGate(serverId, tag, manifest), log);
                }
            }
            return new GateResult(verdict, all);
        } catch (IOException e) {
            // transport/auth/scan error is a misconfiguration, not a security failure
            throw new AbortException("[CXRay] API error: " + e.getMessage());
        }
    }

    private static String merge(String verdict, List<Finding> all, String name, GateResult r, PrintStream log) {
        log.println("  " + name + ": " + r.verdict.toUpperCase() + " (" + r.findings.size() + ")");
        all.addAll(r.findings);
        return GateResult.worst(verdict, r.verdict);
    }

    private String localTarget() {
        List<String> parts = new ArrayList<>();
        if (configPath != null) parts.add(configPath);
        if (manifestPath != null) parts.add(manifestPath);
        if (modelFilePath != null) parts.add(modelFilePath);
        return parts.isEmpty() ? "workspace" : String.join(", ", parts);
    }

    /** Compact one-line build description: verdict + severity tally (shows *why* a build blocked). */
    private static String describe(GateResult result) {
        int crit = 0, high = 0, other = 0;
        for (Finding f : result.findings) {
            String s = f.severity == null ? "" : f.severity.toLowerCase();
            if ("critical".equals(s)) crit++;
            else if ("high".equals(s)) high++;
            else other++;
        }
        StringBuilder sb = new StringBuilder("CXRay: ").append(result.verdict.toUpperCase());
        if (!result.findings.isEmpty()) {
            sb.append(" — ").append(result.findings.size()).append(" finding")
              .append(result.findings.size() == 1 ? "" : "s");
            StringBuilder by = new StringBuilder();
            if (crit > 0) by.append(crit).append(" critical");
            if (high > 0) by.append(by.length() > 0 ? ", " : "").append(high).append(" high");
            if (other > 0) by.append(by.length() > 0 ? ", " : "").append(other).append(" other");
            if (by.length() > 0) sb.append(" (").append(by).append(")");
        }
        return sb.toString();
    }

    private static String read(FilePath ws, String path, PrintStream log) throws InterruptedException, IOException {
        if (path == null) return null;
        // Keep reads inside the workspace: reject absolute paths and any ".." traversal.
        String norm = path.replace('\\', '/');
        if (norm.startsWith("/") || norm.matches("^[A-Za-z]:.*")
                || norm.equals("..") || norm.startsWith("../") || norm.endsWith("/..") || norm.contains("/../")) {
            throw new AbortException("[CXRay] Invalid path (must be a relative path inside the workspace): " + path);
        }
        FilePath fp = ws.child(path);
        if (!fp.exists()) { log.println("[CXRay] WARNING: file not found in workspace: " + path); return null; }
        log.println("[CXRay] Reading " + path);
        return fp.readToString();
    }

    @Extension
    @Symbol("cxrayGate")
    public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {

        @Override
        public boolean isApplicable(Class<? extends AbstractProject> jobType) {
            return true;
        }

        @Override
        public String getDisplayName() {
            return "CXRay Security Gate";
        }

        public ListBoxModel doFillFailOnItems() {
            ListBoxModel m = new ListBoxModel();
            m.add("fail — block only on FAIL (default)", "fail");
            m.add("review — block on REVIEW too", "review");
            return m;
        }

        public ListBoxModel doFillCredentialsIdItems(@AncestorInPath Item item, @QueryParameter String credentialsId) {
            return credentialItems(item, credentialsId);
        }

        public ListBoxModel doFillRegistryCredentialsIdItems(@AncestorInPath Item item, @QueryParameter String registryCredentialsId) {
            return credentialItems(item, registryCredentialsId);
        }

        // Gate credential enumeration on permission so unprivileged users can't list credential IDs
        // via the form-fill endpoint (Jenkins SECURITY-hardening convention).
        private ListBoxModel credentialItems(Item item, String current) {
            StandardListBoxModel result = new StandardListBoxModel();
            if (item == null) {
                if (!Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
                    return result.includeCurrentValue(current);
                }
            } else if (!item.hasPermission(Item.EXTENDED_READ)
                    && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
                return result.includeCurrentValue(current);
            }
            return result.includeEmptyValue()
                    .includeMatchingAs(ACL.SYSTEM, item, StandardUsernamePasswordCredentials.class,
                            Collections.emptyList(), CredentialsMatchers.always())
                    .includeCurrentValue(current);
        }

        public FormValidation doCheckImageId(@QueryParameter String value, @QueryParameter String mode) {
            if ("api".equals(mode) && (value == null || value.trim().isEmpty())) {
                return FormValidation.warning("API mode needs an Image ID.");
            }
            return FormValidation.ok();
        }
    }
}
