package io.cxray.jenkins;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import hudson.model.FreeStyleBuild;
import hudson.model.FreeStyleProject;
import hudson.model.Result;
import java.nio.charset.StandardCharsets;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.SingleFileSCM;

/**
 * End-to-end integration tests for the local (offline) gate: a risky Modelfile must FAIL the build
 * (with a report action attached), a clean one must SUCCEED, and missing inputs is an ERROR.
 * (API-mode + WireMock is a follow-up.)
 */
public class CXRayGateStepTest {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    private static CXRayGateStep localModelStep(String path) {
        CXRayGateStep s = new CXRayGateStep();
        s.setMode("local");
        s.setModelFilePath(path);
        return s;
    }

    private static SingleFileSCM file(String name, String content) {
        return new SingleFileSCM(name, content.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    public void riskyModelfileFailsBuild() throws Exception {
        FreeStyleProject p = j.createFreeStyleProject();
        p.setScm(file("Modelfile", "FROM http://mirror.example.com/model.gguf\nENV OLLAMA_HOST=0.0.0.0"));
        p.getBuildersList().add(localModelStep("Modelfile"));

        FreeStyleBuild b = j.buildAndAssertStatus(Result.FAILURE, p);
        CXRayReportAction a = b.getAction(CXRayReportAction.class);
        assertNotNull("report action should be attached even on failure", a);
        assertEquals("fail", a.getVerdict());
        assertTrue(a.getFindingCount() > 0);
    }

    @Test
    public void cleanModelfilePassesBuild() throws Exception {
        FreeStyleProject p = j.createFreeStyleProject();
        p.setScm(file("Modelfile", "FROM llama3.2:3b\nSYSTEM You are a helpful assistant."));
        p.getBuildersList().add(localModelStep("Modelfile"));

        FreeStyleBuild b = j.buildAndAssertSuccess(p);
        CXRayReportAction a = b.getAction(CXRayReportAction.class);
        assertNotNull(a);
        assertEquals("pass", a.getVerdict());
    }

    @Test
    public void dryRunReportsButDoesNotFail() throws Exception {
        FreeStyleProject p = j.createFreeStyleProject();
        p.setScm(file("Modelfile", "FROM http://mirror.example.com/model.gguf\nENV OLLAMA_HOST=0.0.0.0"));
        CXRayGateStep s = localModelStep("Modelfile");
        s.setDryRun(true);
        p.getBuildersList().add(s);

        // same risky Modelfile that FAILs above — dry-run must SUCCEED but still attach the fail report
        FreeStyleBuild b = j.buildAndAssertSuccess(p);
        CXRayReportAction a = b.getAction(CXRayReportAction.class);
        assertNotNull(a);
        assertEquals("fail", a.getVerdict());
        assertTrue(a.getFindingCount() > 0);
    }

    @Test
    public void noInputsIsError() throws Exception {
        FreeStyleProject p = j.createFreeStyleProject();
        CXRayGateStep s = new CXRayGateStep();
        s.setMode("local");
        p.getBuildersList().add(s);
        // AbortException (misconfiguration) -> build FAILURE
        j.buildAndAssertStatus(Result.FAILURE, p);
    }
}
