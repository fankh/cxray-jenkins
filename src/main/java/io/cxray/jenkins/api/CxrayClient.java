package io.cxray.jenkins.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.cxray.jenkins.local.GateResult;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * Thin CXRay API client (JDK {@link HttpClient} — no shaded deps). Sends the IP-bound access-key
 * bearer, GETs each gate endpoint, and hands the parsed JSON to {@link CxrayApiGate}. A 3xx redirect
 * to login is surfaced as an auth error (distinct from a security finding).
 */
public class CxrayClient {

    private final String baseUrl; // console origin + /api, no trailing slash
    private final String bearer;
    private final HttpClient http;
    private final int timeoutSec;
    private final ObjectMapper mapper = new ObjectMapper();

    public CxrayClient(String baseUrl, String accessKey, String secretKey, int timeoutSec) {
        this.baseUrl = baseUrl.replaceAll("/+$", "");
        this.bearer = Auth.bearer(accessKey, secretKey);
        this.timeoutSec = timeoutSec > 0 ? timeoutSec : 30;
        this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(this.timeoutSec)).build();
    }

    private JsonNode get(String path) throws IOException, InterruptedException {
        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .header("Authorization", bearer)
                .header("Accept", "application/json")
                .timeout(Duration.ofSeconds(timeoutSec))
                .GET().build();
        HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());
        int sc = res.statusCode();
        if (sc >= 300 && sc < 400) {
            throw new IOException("auth failed for " + path + " (redirected to login — check access key / IP allow-list)");
        }
        if (sc != 200) {
            throw new IOException(path + " -> HTTP " + sc);
        }
        return mapper.readTree(res.body());
    }

    public GateResult cveGate(String imageId, double maxCvss, boolean failOnKev) throws IOException, InterruptedException {
        return CxrayApiGate.cve(get("/image/cve/gate/" + enc(imageId) + "?maxCvss=" + maxCvss + "&failOnKev=" + failOnKev));
    }

    public GateResult licenseGate(String imageId) throws IOException, InterruptedException {
        return CxrayApiGate.license(get("/license/policy/" + enc(imageId)));
    }

    public GateResult secretsGate(String imageId) throws IOException, InterruptedException {
        return CxrayApiGate.secrets(get("/image/secrets/" + enc(imageId)));
    }

    public GateResult aiGate(String imageId) throws IOException, InterruptedException {
        return CxrayApiGate.ai(get("/ai/scan/" + enc(imageId)));
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }
}
