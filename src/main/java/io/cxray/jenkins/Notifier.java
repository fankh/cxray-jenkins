package io.cxray.jenkins;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.PrintStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * Best-effort webhook notifier — posts a compact message when the gate blocks a build. The payload is
 * {@code {"text": "..."}}, which Slack and Microsoft Teams incoming webhooks (and most generic
 * receivers) accept. Never fails the build: any error is logged and swallowed.
 */
public final class Notifier {

    private Notifier() {}

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static void gateFailed(String webhookUrl, String verdict, String mode, String target,
                                  int findingCount, String buildUrl, int timeoutSec, PrintStream log) {
        if (webhookUrl == null || webhookUrl.trim().isEmpty()) return;
        String url = webhookUrl.trim();
        if (!url.regionMatches(true, 0, "http", 0, 4)) {
            log.println("[CXRay] notify: skipped — webhook URL is not http(s)");
            return;
        }
        int t = timeoutSec > 0 ? timeoutSec : 30;
        try {
            String text = "CXRay gate " + verdict.toUpperCase() + " — " + mode + " · " + target
                    + " — " + findingCount + " finding" + (findingCount == 1 ? "" : "s")
                    + (buildUrl != null ? "  " + buildUrl : "");
            String json = "{\"text\":" + MAPPER.writeValueAsString(text) + "}";
            HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(t)).build();
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .header("Content-Type", "application/json")
                    .timeout(Duration.ofSeconds(t))
                    .POST(HttpRequest.BodyPublishers.ofString(json, StandardCharsets.UTF_8))
                    .build();
            HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (res.statusCode() >= 300) {
                log.println("[CXRay] notify: webhook returned HTTP " + res.statusCode() + " — ignored");
            } else {
                log.println("[CXRay] notify: sent gate-failure webhook");
            }
        } catch (IllegalArgumentException e) {
            log.println("[CXRay] notify: invalid webhook URL — ignored");
        } catch (IOException e) {
            log.println("[CXRay] notify: webhook failed (" + e.getMessage() + ") — ignored");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.println("[CXRay] notify: interrupted — ignored");
        }
    }
}
