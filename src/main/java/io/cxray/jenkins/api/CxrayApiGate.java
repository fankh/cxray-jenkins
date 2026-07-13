package io.cxray.jenkins.api;

import com.fasterxml.jackson.databind.JsonNode;
import io.cxray.jenkins.local.Finding;
import io.cxray.jenkins.local.GateResult;
import java.util.ArrayList;
import java.util.List;

/**
 * Normalize CXRay's server-side gate responses into a common {verdict, findings} shape — the same
 * mapping the cxray-gate CLI's {@code normCveGate}/{@code normLicenseGate}/… use. Pure (operates on
 * a parsed JsonNode) so it's unit-testable without a live server.
 */
public final class CxrayApiGate {

    private CxrayApiGate() {}

    /** GET /image/cve/gate/{id} — fail on any KEV or CVSS &ge; threshold (no review level). */
    public static GateResult cve(JsonNode r) {
        List<Finding> f = new ArrayList<>();
        String verdict = "fail".equals(txt(r, "verdict")) ? "fail" : "pass";
        JsonNode kev = r.get("kev");
        if (isArray(kev)) for (JsonNode c : kev) f.add(new Finding("cve", "critical", txt(c, "cveCode"), "base " + txt(c, "base") + " · KEV", 0));
        JsonNode crit = r.get("critical");
        if (isArray(crit)) for (JsonNode c : crit) {
            String code = txt(c, "cveCode");
            if (!inArray(kev, "cveCode", code)) f.add(new Finding("cve", "critical", code, "base " + txt(c, "base"), 0));
        }
        return new GateResult(verdict, f);
    }

    /** GET /license/policy/{id} — fail on deny-listed licenses; review-listed → review. */
    public static GateResult license(JsonNode r) {
        List<Finding> f = new ArrayList<>();
        String v = txt(r, "verdict");
        String verdict = "fail".equals(v) ? "fail" : (intt(r, "reviewCount") > 0 ? "review" : "pass");
        JsonNode deny = r.get("deny");
        if (isArray(deny)) for (JsonNode d : deny) f.add(new Finding("license", "critical", txt(d, "name"), licenses(d), 0));
        JsonNode rev = r.get("review");
        if (isArray(rev)) for (JsonNode d : rev) f.add(new Finding("license", "medium", txt(d, "name"), licenses(d), 0));
        return new GateResult(verdict, f);
    }

    /** GET /image/secrets/{id} — verdict is already pass/review/fail. */
    public static GateResult secrets(JsonNode r) {
        List<Finding> f = new ArrayList<>();
        String verdict = norm(txt(r, "verdict"));
        JsonNode fs = r.get("findings");
        if (isArray(fs)) for (JsonNode x : fs) {
            String path = txt(x, "path");
            f.add(new Finding("secrets", txt(x, "severity", "medium"), txt(x, "kind"),
                    (path.isEmpty() ? "" : path + "/") + txt(x, "fileName"), 0));
        }
        return new GateResult(verdict, f);
    }

    /** GET /ai/scan/{id} — AI/model supply-chain; verdict already pass/review/fail. */
    public static GateResult ai(JsonNode r) {
        List<Finding> f = new ArrayList<>();
        String verdict = norm(txt(r, "verdict"));
        int unsafe = intt(r, "unsafeArtifactCount");
        if (unsafe > 0) f.add(new Finding("ai", "critical", "unsafe-artifact", unsafe + " unsafe-serialization model artifact(s) — deserialization RCE", 0));
        int rev = intt(r, "reviewArtifactCount");
        if (rev > 0) f.add(new Finding("ai", "medium", "review-artifact", rev + " model artifact(s) to review", 0));
        return new GateResult(verdict, f);
    }

    /**
     * GET /image/packet/gate/{id} — egress over sandbox-captured network flows. One finding per
     * public-egress flow. verdict is pass/fail/review, or "skip" when no behavioural capture ran —
     * "skip" is PRESERVED (not collapsed to pass) so the build shows the check didn't perform.
     */
    public static GateResult packet(JsonNode r) {
        List<Finding> f = new ArrayList<>();
        String v = txt(r, "verdict");
        String verdict = "skip".equals(v) ? "skip" : norm(v);
        String sev = "fail".equals(verdict) ? "critical" : "medium";
        JsonNode egress = r.get("publicEgress");
        if (isArray(egress)) for (JsonNode e : egress) {
            String ip = txt(e, "targetIp");
            String port = txt(e, "targetPort");
            String proto = txt(e, "protocol");
            String dest = ip + (port.isEmpty() ? "" : ":" + port) + (proto.isEmpty() ? "" : "/" + proto);
            f.add(new Finding("packet", sev, dest, "public egress — outbound to a non-private address", 0));
        }
        return new GateResult(verdict, f);
    }

    /** POST /mcp/gate — OWASP-Agentic rules; verdict already pass/review/fail, one finding per non-pass rule. */
    public static GateResult mcp(JsonNode r) {
        List<Finding> f = new ArrayList<>();
        String verdict = norm(txt(r, "verdict"));
        JsonNode rules = r.get("rules");
        if (isArray(rules)) for (JsonNode ru : rules) {
            String status = txt(ru, "status");
            if ("pass".equals(status)) continue;
            String sev = "fail".equals(status) ? "critical" : "medium";
            String owasp = txt(ru, "owasp");
            String detail = txt(ru, "detail");
            f.add(new Finding("mcp", sev, txt(ru, "title"),
                    (detail.isEmpty() ? "" : detail + (owasp.isEmpty() ? "" : " · ")) + owasp, 0));
        }
        return new GateResult(verdict, f);
    }

    // ── helpers ──
    private static String norm(String v) { return "fail".equals(v) ? "fail" : "review".equals(v) ? "review" : "pass"; }
    private static boolean isArray(JsonNode n) { return n != null && n.isArray(); }
    private static String txt(JsonNode n, String field) { return txt(n, field, ""); }
    private static String txt(JsonNode n, String field, String def) {
        if (n == null) return def;
        JsonNode v = n.get(field);
        return (v == null || v.isNull()) ? def : v.asText(def);
    }
    private static int intt(JsonNode n, String field) {
        if (n == null) return 0;
        JsonNode v = n.get(field);
        return (v == null || v.isNull()) ? 0 : v.asInt(0);
    }
    private static boolean inArray(JsonNode arr, String field, String value) {
        if (!isArray(arr)) return false;
        for (JsonNode x : arr) if (value.equals(txt(x, field))) return true;
        return false;
    }
    private static String licenses(JsonNode d) {
        JsonNode l = d.get("licenses");
        if (!isArray(l)) return "";
        List<String> s = new ArrayList<>();
        for (JsonNode x : l) s.add(x.asText());
        return String.join(", ", s);
    }
}
