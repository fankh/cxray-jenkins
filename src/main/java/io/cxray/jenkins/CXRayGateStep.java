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
import java.io.IOException;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javax.annotation.Nonnull;
import jenkins.tasks.SimpleBuildStep;
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
    private String apiUrl; // overrides the global config

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
    public String getApiUrl() { return apiUrl; }
    @DataBoundSetter public void setApiUrl(String v) { this.apiUrl = fix(v); }

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
    public void perform(@Nonnull Run<?, ?> run, @Nonnull FilePath workspace, @Nonnull EnvVars env,
                        @Nonnull Launcher launcher, @Nonnull TaskListener listener)
            throws InterruptedException, IOException {
        PrintStream log = listener.getLogger();
        GateResult result = "api".equals(mode) ? performApi(run, log) : performLocal(workspace, log);

        for (Finding f : result.findings) {
            log.println(String.format("  [%s] %-8s %s — %s%s",
                    f.check, f.severity.toUpperCase(), f.title, f.detail,
                    f.line > 0 ? " (line " + f.line + ")" : ""));
        }
        log.println("[CXRay] Verdict: " + result.verdict.toUpperCase()
                + " (" + result.findings.size() + " finding" + (result.findings.size() == 1 ? "" : "s") + ")");

        boolean block = "fail".equals(result.verdict)
                || ("review".equals(result.verdict) && "review".equals(failOn));
        if (block) {
            throw new AbortException("[CXRay] Gate " + result.verdict.toUpperCase()
                    + " — failing the build (fail-on=" + failOn + ").");
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
    private GateResult performApi(Run<?, ?> run, PrintStream log) throws AbortException, InterruptedException {
        String base = apiUrl != null ? apiUrl : (CXRayGlobalConfiguration.get() != null ? CXRayGlobalConfiguration.get().getApiUrl() : null);
        if (base == null || base.isEmpty()) throw new AbortException("[CXRay] No API URL — set it in Manage Jenkins → System, or per-job.");
        if (credentialsId == null) throw new AbortException("[CXRay] API mode needs CXRay access-key credentials.");
        StandardUsernamePasswordCredentials c = CredentialsProvider.findCredentialById(
                credentialsId, StandardUsernamePasswordCredentials.class, run, Collections.emptyList());
        if (c == null) throw new AbortException("[CXRay] Credentials not found: " + credentialsId);

        int timeout = CXRayGlobalConfiguration.get() != null ? CXRayGlobalConfiguration.get().getTimeoutSec() : 30;
        CxrayClient client = new CxrayClient(base, c.getUsername(), c.getPassword().getPlainText(), timeout);

        List<String> want = new ArrayList<>();
        for (String g : gates.split(",")) { g = g.trim().toLowerCase(); if (!g.isEmpty()) want.add(g); }

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
            if (want.contains("cve")) verdict = merge(verdict, all, "CVE/KEV", client.cveGate(id, maxCvss, failOnKev), log);
            if (want.contains("license")) verdict = merge(verdict, all, "License", client.licenseGate(id), log);
            if (want.contains("secrets")) verdict = merge(verdict, all, "Secrets", client.secretsGate(id), log);
            if (want.contains("ai")) verdict = merge(verdict, all, "AI supply-chain", client.aiGate(id), log);
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

    private static String read(FilePath ws, String path, PrintStream log) throws InterruptedException, IOException {
        if (path == null) return null;
        FilePath fp = ws.child(path);
        if (!fp.exists()) { log.println("[CXRay] WARNING: file not found in workspace: " + path); return null; }
        log.println("[CXRay] Reading " + path);
        return fp.readToString();
    }

    @Extension
    public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {

        @Override
        public boolean isApplicable(Class<? extends AbstractProject> jobType) {
            return true;
        }

        @Nonnull
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
            StandardListBoxModel result = new StandardListBoxModel();
            if (item != null && !item.hasPermission(Item.CONFIGURE)) {
                return result.includeCurrentValue(credentialsId);
            }
            return result.includeEmptyValue()
                    .includeMatchingAs(ACL.SYSTEM, item, StandardUsernamePasswordCredentials.class,
                            Collections.emptyList(), CredentialsMatchers.always())
                    .includeCurrentValue(credentialsId);
        }

        public FormValidation doCheckImageId(@QueryParameter String value, @QueryParameter String mode) {
            if ("api".equals(mode) && (value == null || value.trim().isEmpty())) {
                return FormValidation.warning("API mode needs an Image ID.");
            }
            return FormValidation.ok();
        }
    }
}
