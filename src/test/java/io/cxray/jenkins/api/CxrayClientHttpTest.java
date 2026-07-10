package io.cxray.jenkins.api;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.sun.net.httpserver.HttpServer;
import io.cxray.jenkins.local.GateResult;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Exercises the real {@link CxrayClient} HTTP path (JDK {@code HttpClient}) against an in-JVM stub
 * server — the one code path that had no live coverage (the pure normalization is covered by
 * {@link CxrayApiGateTest}). Uses {@code com.sun.net.httpserver} so the test stays dependency-free,
 * consistent with the plugin's minimal-deps design (no WireMock on the classpath).
 */
public class CxrayClientHttpTest {

    private HttpServer server;
    private String base;
    private volatile String lastAuth;
    private volatile String lastBody;
    private final AtomicInteger analyzeCalls = new AtomicInteger();

    @Before
    public void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", ex -> {
            lastAuth = ex.getRequestHeaders().getFirst("Authorization");
            try (InputStream in = ex.getRequestBody()) {
                lastBody = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            }
            String path = ex.getRequestURI().getPath();
            int code = 200;
            String body;
            if (path.equals("/image/check/repo")) {
                body = "{\"data\":\"IMG-1\"}";
            } else if (path.equals("/image/IMG-1")) {
                boolean analyzing = analyzeCalls.getAndIncrement() == 0; // true on first poll, then false
                body = "{\"data\":{\"nowAnalyzing\":" + analyzing + "}}";
            } else if (path.equals("/image/REDIR")) {
                ex.getResponseHeaders().set("Location", "/login");
                ex.sendResponseHeaders(302, -1); // simulate the login redirect an unauth'd request gets
                ex.close();
                return;
            } else if (path.startsWith("/image/cve/gate/")) {
                body = "{\"verdict\":\"fail\",\"kev\":[{\"cveCode\":\"CVE-2024-0001\",\"base\":\"9.8\"}]}";
            } else if (path.startsWith("/license/policy/")) {
                body = "{\"verdict\":\"pass\",\"reviewCount\":1,\"review\":[{\"name\":\"pkg\",\"licenses\":[\"LGPL-3.0\"]}]}";
            } else if (path.startsWith("/image/secrets/")) {
                body = "{\"verdict\":\"fail\",\"findings\":[{\"severity\":\"high\",\"kind\":\"aws-key\",\"path\":\"app\",\"fileName\":\".env\"}]}";
            } else if (path.startsWith("/ai/scan/")) {
                body = "{\"verdict\":\"fail\",\"unsafeArtifactCount\":2,\"reviewArtifactCount\":1}";
            } else if (path.equals("/mcp/gate")) {
                body = "{\"serverId\":\"svc\",\"verdict\":\"fail\",\"rules\":["
                        + "{\"id\":\"poisoning\",\"title\":\"No poisoning\",\"owasp\":\"ASI01\",\"status\":\"fail\",\"detail\":\"1 signal\"},"
                        + "{\"id\":\"drift\",\"title\":\"No drift\",\"owasp\":\"ASI04\",\"status\":\"pass\",\"detail\":\"ok\"}]}";
            } else {
                body = "{}";
                code = 404;
            }
            byte[] out = body.getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().set("Content-Type", "application/json");
            ex.sendResponseHeaders(code, out.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(out);
            }
        });
        server.start();
        base = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @After
    public void tearDown() {
        if (server != null) server.stop(0);
    }

    @Test
    public void startScanParsesImageIdAndSendsBearerAndBody() throws Exception {
        CxrayClient c = new CxrayClient(base, "AK", "SK", 5);
        String id = c.startScan("registry.example", "svc", "v1", "ruser", "rpass");
        assertEquals("IMG-1", id);
        assertEquals("the IP-bound access-key bearer is actually sent", Auth.bearer("AK", "SK"), lastAuth);
        assertTrue(lastBody.contains("\"repo\":\"registry.example\""));
        assertTrue(lastBody.contains("\"image\":\"svc\""));
        assertTrue(lastBody.contains("\"tag\":\"v1\""));
        assertTrue(lastBody.contains("\"username\":\"ruser\""));
    }

    @Test
    public void isAnalyzingPollsTrueThenFalse() throws Exception {
        CxrayClient c = new CxrayClient(base, "AK", "SK", 5);
        assertTrue(c.isAnalyzing("IMG-1"));
        assertFalse(c.isAnalyzing("IMG-1"));
    }

    @Test
    public void cveGateFailsOnKev() throws Exception {
        GateResult g = new CxrayClient(base, "AK", "SK", 5).cveGate("IMG-1", 9.0, true);
        assertEquals("fail", g.verdict);
        assertEquals(1, g.findings.size());
    }

    @Test
    public void licenseGateReviews() throws Exception {
        GateResult g = new CxrayClient(base, "AK", "SK", 5).licenseGate("IMG-1");
        assertEquals("review", g.verdict);
    }

    @Test
    public void secretsGateFails() throws Exception {
        GateResult g = new CxrayClient(base, "AK", "SK", 5).secretsGate("IMG-1");
        assertEquals("fail", g.verdict);
        assertEquals(1, g.findings.size());
    }

    @Test
    public void aiGateFailsOnUnsafeArtifacts() throws Exception {
        GateResult g = new CxrayClient(base, "AK", "SK", 5).aiGate("IMG-1");
        assertEquals("fail", g.verdict);
    }

    @Test
    public void mcpGate_postsManifestAndNormalizesRules() throws Exception {
        CxrayClient c = new CxrayClient(base, "AK", "SK", 5);
        GateResult g = c.mcpGate("svc", "v1", "{\"tools\":[{\"name\":\"run\"}]}");
        assertEquals("fail", g.verdict);
        assertEquals(1, g.findings.size());                 // only the non-pass rule
        assertEquals(Auth.bearer("AK", "SK"), lastAuth);    // authenticated POST
        assertTrue(lastBody.contains("\"serverId\":\"svc\""));
        assertTrue(lastBody.contains("\"manifest\""));
    }

    @Test
    public void redirectToLoginSurfacedAsAuthError() {
        CxrayClient c = new CxrayClient(base, "AK", "SK", 5);
        try {
            c.isAnalyzing("REDIR");
            fail("expected an auth error when the API redirects to login");
        } catch (Exception e) {
            assertTrue("message should explain the auth failure: " + e.getMessage(),
                    e.getMessage().toLowerCase().contains("auth failed"));
        }
    }
}
