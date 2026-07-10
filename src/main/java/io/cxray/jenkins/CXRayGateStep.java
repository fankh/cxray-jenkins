package io.cxray.jenkins;

import hudson.AbortException;
import hudson.EnvVars;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractProject;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import io.cxray.jenkins.local.Finding;
import io.cxray.jenkins.local.GateResult;
import io.cxray.jenkins.local.LocalAnalyzers;
import java.io.IOException;
import java.io.PrintStream;
import javax.annotation.Nonnull;
import jenkins.tasks.SimpleBuildStep;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

/**
 * CXRay Security Gate — <b>Method B (local / offline)</b>.
 *
 * <p>Analyzes agent/AI-security artifacts in the workspace with no CXRay server and no credentials:
 * an MCP server config (transport + identity posture), a tool manifest (poisoning), and/or an
 * Ollama Modelfile / model-server config (supply-chain &amp; exposure). Fails the build when the
 * worst verdict is {@code fail} (or {@code review} when {@code failOn=review}). Works in Freestyle
 * and Pipeline (via {@link SimpleBuildStep}).
 *
 * <p>Method A (CXRay API scan-and-gate) is added in a later phase.
 */
public class CXRayGateStep extends Builder implements SimpleBuildStep {

    private String configPath;     // mcp.json / server.json  -> transport + identity
    private String manifestPath;   // tools/list manifest     -> poisoning
    private String modelFilePath;  // Ollama Modelfile        -> model runtime
    private String failOn = "fail";

    @DataBoundConstructor
    public CXRayGateStep() {
        // all inputs are optional and set via @DataBoundSetter
    }

    public String getConfigPath() { return configPath; }
    @DataBoundSetter public void setConfigPath(String configPath) { this.configPath = fix(configPath); }

    public String getManifestPath() { return manifestPath; }
    @DataBoundSetter public void setManifestPath(String manifestPath) { this.manifestPath = fix(manifestPath); }

    public String getModelFilePath() { return modelFilePath; }
    @DataBoundSetter public void setModelFilePath(String modelFilePath) { this.modelFilePath = fix(modelFilePath); }

    public String getFailOn() { return failOn; }
    @DataBoundSetter public void setFailOn(String failOn) { this.failOn = "review".equals(failOn) ? "review" : "fail"; }

    private static String fix(String s) {
        return (s == null || s.trim().isEmpty()) ? null : s.trim();
    }

    @Override
    public void perform(@Nonnull Run<?, ?> run, @Nonnull FilePath workspace, @Nonnull EnvVars env,
                        @Nonnull Launcher launcher, @Nonnull TaskListener listener)
            throws InterruptedException, IOException {
        PrintStream log = listener.getLogger();
        log.println("[CXRay] Local (offline) agent-security gate");

        String config = read(workspace, configPath, log);
        String manifest = read(workspace, manifestPath, log);
        String model = read(workspace, modelFilePath, log);
        if (config == null && manifest == null && model == null) {
            // misconfiguration, not a security finding
            throw new AbortException("[CXRay] No inputs — set at least one of configPath / manifestPath / modelFilePath.");
        }

        GateResult result = LocalAnalyzers.run(config, manifest, model);
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

    private static String read(FilePath ws, String path, PrintStream log) throws InterruptedException, IOException {
        if (path == null) return null;
        FilePath fp = ws.child(path);
        if (!fp.exists()) {
            log.println("[CXRay] WARNING: file not found in workspace: " + path);
            return null;
        }
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
            return "CXRay Security Gate (local)";
        }

        public ListBoxModel doFillFailOnItems() {
            ListBoxModel m = new ListBoxModel();
            m.add("fail — block only on FAIL (default)", "fail");
            m.add("review — block on REVIEW too", "review");
            return m;
        }

        public FormValidation doCheckConfigPath(@QueryParameter String value,
                                                @QueryParameter String manifestPath,
                                                @QueryParameter String modelFilePath) {
            if ((value == null || value.trim().isEmpty())
                    && (manifestPath == null || manifestPath.trim().isEmpty())
                    && (modelFilePath == null || modelFilePath.trim().isEmpty())) {
                return FormValidation.warning("Set at least one of config / manifest / model file.");
            }
            return FormValidation.ok();
        }
    }
}
