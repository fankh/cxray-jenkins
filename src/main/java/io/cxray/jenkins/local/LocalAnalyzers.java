package io.cxray.jenkins.local;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Offline agent/AI-security analyzers — pure, dependency-free Java ports of the CXRay console/CLI
 * analyzers ({@code functions/transportPosture.ts}, {@code identityPosture.ts},
 * {@code modelRuntime.ts}, {@code mcpIntegrity.ts}) and {@code cxray-main AgentPostureService}.
 * Keep the regexes in sync with those sources (the accepted cross-artifact duplication).
 *
 * <p>Everything works on raw text, so no JSON dependency is needed for the local gate. The
 * per-tool capability matrix (which needs structured tool parsing) is a later phase.
 */
public final class LocalAnalyzers {

    private LocalAnalyzers() {}

    // ── E19.2 transport & launch posture ──────────────────────────────────────
    private static final Pattern FETCH_EXEC = Pattern.compile("\\b(npx|bunx|pnpm\\s+dlx|uvx|pipx\\s+run|uv\\s+run|pip\\s+install|go\\s+run|deno\\s+run)\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern SHELL_EXEC = Pattern.compile("\\b(sh|bash|zsh)\\s+-c\\b|\\|\\s*(sh|bash)\\b|&&|;\\s*\\w|\\bcurl\\b.*\\|\\s*(sh|bash)", Pattern.CASE_INSENSITIVE);
    private static final Pattern HTTP_URL = Pattern.compile("[\"'\\s(=]http://(?!localhost|127\\.0\\.0\\.1)", Pattern.CASE_INSENSITIVE);
    private static final Pattern T_SECRET = Pattern.compile("\\b(api[_-]?key|secret|token|password)\\b\\s*[:=]\\s*[\"']?[^\\s\"']{6,}|sk-[a-z0-9]{6,}|ghp_[a-z0-9]{6,}|xox[baprs]-", Pattern.CASE_INSENSITIVE);
    private static final Pattern PINNED = Pattern.compile("@\\d+\\.\\d+|@sha256:|@[0-9a-f]{7,}\\b|:\\d+\\.\\d+", Pattern.CASE_INSENSITIVE);
    private static final Pattern HAS_LAUNCH = Pattern.compile("\"command\"\\s*:|\"args\"\\s*:|\\bnpx\\b|\\buvx\\b|\"transport\"\\s*:|\"url\"\\s*:\\s*\"https?:|\"type\"\\s*:\\s*\"(stdio|http|sse|streamable)", Pattern.CASE_INSENSITIVE);

    public static GateResult analyzeTransport(String blob) {
        List<Finding> f = new ArrayList<>();
        if (blob == null) blob = "";
        if (!HAS_LAUNCH.matcher(blob).find()) return new GateResult("pass", f); // no launch config = not applicable
        int penalty = 0;
        boolean fetchExec = FETCH_EXEC.matcher(blob).find();
        boolean pinned = PINNED.matcher(blob).find();
        if (fetchExec && !pinned) { penalty += 60; f.add(new Finding("transport", "critical", "Launch command", "unpinned fetch-and-execute launcher (npx/uvx/…) — remote code runs at startup", 0)); }
        else if (fetchExec) { penalty += 12; f.add(new Finding("transport", "medium", "Launch command", "fetch-and-execute launcher, but a version/digest pin is present", 0)); }
        if (HTTP_URL.matcher(blob).find()) { penalty += 25; f.add(new Finding("transport", "high", "Transport TLS", "plaintext http:// transport — tool traffic is MITM-able", 0)); }
        if (SHELL_EXEC.matcher(blob).find()) { penalty += 12; f.add(new Finding("transport", "medium", "Shell execution", "launch goes through a shell (sh -c / pipe) — command-injection surface", 0)); }
        if (T_SECRET.matcher(blob).find()) { penalty += 22; f.add(new Finding("transport", "high", "Inline credentials", "a secret/token is embedded in the launch args or env", 0)); }
        int score = Math.max(0, Math.min(100, 100 - penalty));
        String risk = score >= 80 ? "low" : score >= 55 ? "medium" : score >= 30 ? "high" : "critical";
        String verdict = ("critical".equals(risk) || "high".equals(risk)) ? "fail" : "medium".equals(risk) ? "review" : "pass";
        return new GateResult(verdict, f);
    }

    // ── E34.1 identity & authorization posture ────────────────────────────────
    private static final Pattern STATIC_KEY = Pattern.compile("\\b(api[_-]?key|access[_-]?token|secret[_-]?key|shared\\s+secret|static\\s+key)\\b|sk-[a-z0-9]{6}|ghp_[a-z0-9]{6}|xox[baprs]-", Pattern.CASE_INSENSITIVE);
    private static final Pattern WORKLOAD_ID = Pattern.compile("spiffe://|\\bspire\\b|workload\\s+identity|\\bwimse\\b|agentic-?jwt|mtls|mutual\\s+tls", Pattern.CASE_INSENSITIVE);
    private static final Pattern OAUTH = Pattern.compile("\\boauth2?\\b|openid|client_credentials|token\\s+endpoint|refresh_token|\\bjwt\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern SCOPED = Pattern.compile("\\bscopes?\\b|least[- ]privilege|expires_?in|\\bttl\\b|short[- ]lived|max_?age|\\bexp\\b|rotat", Pattern.CASE_INSENSITIVE);
    private static final Pattern PREAUTH = Pattern.compile("\\bauthoriz|permission\\s+check|policy\\s+(check|decision|engine)|\\bopa\\b|\\brbac\\b|\\babac\\b|deny[- ]by[- ]default|allow[- ]?list|pre-?action\\s+authoriz", Pattern.CASE_INSENSITIVE);
    private static final Pattern HITL = Pattern.compile("human[- ]in[- ]the[- ]loop|\\bhitl\\b|require\\s+(approval|consent|confirmation)|confirm\\s+before|manual\\s+(review|approval)|out[- ]of[- ]band\\s+approval", Pattern.CASE_INSENSITIVE);
    private static final Pattern IDENTITY_SIGNAL = Pattern.compile("\\bauth|identit|credential|\\btoken\\b|api[_-]?key|access[_-]?token|secret|\\bkey\\b|sk-[a-z0-9]|ghp_|xox[baprs]-|oauth|spiffe|\\bscope|\\brole|\\brbac\\b|approv|login|session|bearer", Pattern.CASE_INSENSITIVE);

    public static GateResult analyzeIdentity(String blobRaw) {
        List<Finding> f = new ArrayList<>();
        String blob = blobRaw == null ? "" : blobRaw.toLowerCase();
        if (!IDENTITY_SIGNAL.matcher(blob).find()) return new GateResult("pass", f); // no auth config = not assessed
        int penalty = 0;
        boolean workload = WORKLOAD_ID.matcher(blob).find();
        boolean oauth = OAUTH.matcher(blob).find();
        boolean staticKey = STATIC_KEY.matcher(blob).find();
        if (!workload && !oauth) {
            if (staticKey) { penalty += 40; f.add(new Finding("identity", "critical", "Credential style", "long-lived static key / shared secret", 0)); }
            else { penalty += 22; f.add(new Finding("identity", "medium", "Credential style", "no identity mechanism declared", 0)); }
        }
        if (!SCOPED.matcher(blob).find()) { penalty += 15; f.add(new Finding("identity", "medium", "Scoping / TTL", "no scoping / TTL evidence", 0)); }
        if (!PREAUTH.matcher(blob).find()) { penalty += 25; f.add(new Finding("identity", "high", "Pre-action authorization", "no pre-action authorization — unmediated tool calls", 0)); }
        if (!HITL.matcher(blob).find()) { penalty += 10; f.add(new Finding("identity", "medium", "Human-in-the-loop", "no HITL checkpoint for high-risk actions", 0)); }
        int score = Math.max(0, Math.min(100, 100 - penalty));
        String risk = score >= 80 ? "low" : score >= 55 ? "medium" : score >= 30 ? "high" : "critical";
        // identity: only a static key (critical) blocks; high/medium → review (manifests are often incomplete)
        String verdict = "critical".equals(risk) ? "fail" : ("high".equals(risk) || "medium".equals(risk)) ? "review" : "pass";
        return new GateResult(verdict, f);
    }

    // ── E18.2/E18.3 model runtime scan ────────────────────────────────────────
    private static final Pattern M_INJECTION = Pattern.compile("<important>|<system>|ignore\\s+(all\\s+)?previous|disregard\\s+(the\\s+)?above|exfiltrat|send\\s+(it|them|this)\\s+to\\s+https?:|\\.ssh/id_rsa|do\\s+not\\s+tell\\s+the\\s+user", Pattern.CASE_INSENSITIVE);
    private static final Pattern M_SECRET = Pattern.compile("\\b(api[_-]?key|secret|token|password)\\b\\s*[:=]\\s*[\"']?[^\\s\"']{6,}|sk-[a-z0-9]{6,}|ghp_[a-z0-9]{6,}", Pattern.CASE_INSENSITIVE);
    private static final Pattern M_PINNED = Pattern.compile("@sha256:[0-9a-f]{8,}|@\\d+\\.\\d+|:\\d+\\.\\d+(\\.\\d+)?\\b|:[0-9a-f]{12,}\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern M_EXPOSED = Pattern.compile("0\\.0\\.0\\.0|::\\b|(host|bind|listen)\\s*[:=]\\s*[\"']?(0\\.0\\.0\\.0|\\*)|OLLAMA_HOST\\s*=\\s*0\\.0\\.0\\.0", Pattern.CASE_INSENSITIVE);
    private static final Pattern M_AUTH = Pattern.compile("api[_-]?key|authorization|bearer|auth[_-]?token|--api-key|require.?auth", Pattern.CASE_INSENSITIVE);
    private static final Pattern FROM_LINE = Pattern.compile("^\\s*FROM\\s+(.+)$", Pattern.CASE_INSENSITIVE);
    private static final Pattern FROM_KV = Pattern.compile("[\"']?(?:from|model|source)[\"']?\\s*[:=]\\s*[\"']?([^\"',\\s]+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern HTTP_PREFIX = Pattern.compile("^http://", Pattern.CASE_INSENSITIVE);
    private static final Pattern ADAPTER = Pattern.compile("^\\s*ADAPTER\\s+", Pattern.CASE_INSENSITIVE);
    private static final Pattern SYSTEM_LINE = Pattern.compile("^\\s*(SYSTEM|TEMPLATE)\\b|\"?system\"?\\s*[:=]", Pattern.CASE_INSENSITIVE);
    private static final Pattern REMOTE_URL = Pattern.compile("https?://", Pattern.CASE_INSENSITIVE);
    private static final Pattern REMOTE_EXT = Pattern.compile("\\.(gguf|bin|safetensors)\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern REMOTE_HOST = Pattern.compile("huggingface|hf\\.co|ollama\\.com/library", Pattern.CASE_INSENSITIVE);

    private static boolean looksRemote(String ref) {
        return REMOTE_URL.matcher(ref).find() || ref.contains("/") || REMOTE_EXT.matcher(ref).find() || REMOTE_HOST.matcher(ref).find();
    }

    public static GateResult analyzeModel(String text) {
        List<Finding> f = new ArrayList<>();
        if (text == null) return new GateResult("pass", f);
        String[] lines = text.split("\\r?\\n");
        boolean exposed = false;
        boolean sawAuth = M_AUTH.matcher(text).find();
        for (int i = 0; i < lines.length; i++) {
            String raw = lines[i];
            int line = i + 1;
            String trimmed = raw.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) continue;
            String ref = null;
            Matcher from = FROM_LINE.matcher(raw);
            if (from.find()) ref = from.group(1).trim();
            else { Matcher kv = FROM_KV.matcher(raw); if (kv.find()) ref = kv.group(1).trim(); }
            if (ref != null) {
                ref = ref.replaceAll("[\"',]+$", "");
                if (HTTP_PREFIX.matcher(ref).find()) f.add(new Finding("model", "high", "insecure-source", "model pulled over plaintext http:// — weights can be swapped in transit", line));
                if (looksRemote(ref) && !M_PINNED.matcher(ref).find()) f.add(new Finding("model", "medium", "unpinned-model", "model source has no digest/version pin — the fetched weights can change silently", line));
            }
            if (ADAPTER.matcher(raw).find()) {
                String aref = raw.replaceAll("^\\s*ADAPTER\\s+", "").trim();
                if (looksRemote(aref) && !M_PINNED.matcher(aref).find()) f.add(new Finding("model", "medium", "unsafe-adapter", "LoRA/adapter from an unpinned source — can alter model behavior", line));
            }
            if (SYSTEM_LINE.matcher(raw).find() && M_INJECTION.matcher(raw).find())
                f.add(new Finding("model", "high", "system-prompt-injection", "baked-in system prompt contains injection / exfiltration instructions", line));
            if (M_EXPOSED.matcher(raw).find()) { exposed = true; f.add(new Finding("model", "high", "exposed-bind", "model server bound to all interfaces (0.0.0.0) — reachable off-host", line)); }
            if (M_SECRET.matcher(raw).find()) f.add(new Finding("model", "medium", "inline-secret", "credential embedded in the model runtime config", line));
        }
        if (exposed && !sawAuth) f.add(new Finding("model", "high", "no-auth", "server exposed (0.0.0.0) with no API-key/auth — an open, abusable inference endpoint", 0));
        int worst = -1;
        for (Finding fn : f) worst = Math.max(worst, "high".equals(fn.severity) ? 2 : "medium".equals(fn.severity) ? 1 : 0);
        String verdict = worst >= 2 ? "fail" : worst >= 0 ? "review" : "pass";
        return new GateResult(verdict, f);
    }

    // ── E19.1/E33.2 tool-poisoning content scan (raw text) ────────────────────
    private static final Pattern P_INJECTION = Pattern.compile("ignore\\s+(all\\s+)?(previous|prior|above)|disregard\\s+(the\\s+|all\\s+)?(previous|prior|instruction)|system\\s*prompt|you\\s+are\\s+now|new\\s+instructions?:|do\\s+not\\s+(tell|inform|mention)|without\\s+(telling|informing|asking)|before\\s+(using|calling)\\s+(any|this|the)\\s+(other\\s+)?tool|<\\s*important\\s*>", Pattern.CASE_INSENSITIVE);
    private static final Pattern P_EXFIL = Pattern.compile("\\.ssh\\b|id_rsa|\\.env\\b|private\\s+key|credential|\\bpassword\\b|\\bsecret\\b|api[_-]?key|access[_-]?token|exfiltrat|send\\s+(it|them|this)\\s+to|upload\\s+(it|them|this)?\\s*to|https?://", Pattern.CASE_INSENSITIVE);
    private static final int[][] HIDDEN_RANGES = {{0x200B, 0x200F}, {0x202A, 0x202E}, {0x2060, 0x2064}, {0x2066, 0x2069}, {0xFEFF, 0xFEFF}};

    public static GateResult analyzePoison(String text) {
        List<Finding> f = new ArrayList<>();
        if (text == null || text.isEmpty()) return new GateResult("pass", f);
        int hidden = -1;
        for (int i = 0; i < text.length() && hidden < 0; i++) {
            int c = text.charAt(i);
            for (int[] r : HIDDEN_RANGES) if (c >= r[0] && c <= r[1]) { hidden = c; break; }
        }
        if (hidden >= 0) f.add(new Finding("poison", "critical", "hidden-unicode", "U+" + Integer.toHexString(hidden).toUpperCase() + " invisible/bidi char", 0));
        Matcher inj = P_INJECTION.matcher(text);
        if (inj.find()) f.add(new Finding("poison", "critical", "injection", inj.group().trim(), 0));
        Matcher exf = P_EXFIL.matcher(text);
        if (exf.find()) f.add(new Finding("poison", "high", "exfiltration", exf.group().trim(), 0));
        int worst = -1;
        for (Finding fn : f) worst = Math.max(worst, "critical".equals(fn.severity) ? 2 : "high".equals(fn.severity) ? 1 : 0);
        String verdict = worst >= 2 ? "fail" : worst >= 1 ? "review" : "pass";
        return new GateResult(verdict, f);
    }

    // ── aggregate: run the analyzers for whichever inputs are provided ─────────
    public static GateResult run(String config, String manifest, String model) {
        List<Finding> all = new ArrayList<>();
        String verdict = "pass";
        if (config != null) {
            GateResult t = analyzeTransport(config);
            GateResult id = analyzeIdentity(config);
            all.addAll(t.findings);
            all.addAll(id.findings);
            verdict = GateResult.worst(verdict, GateResult.worst(t.verdict, id.verdict));
        }
        if (manifest != null) {
            GateResult po = analyzePoison(manifest);          // text: injection / hidden-unicode / exfil
            GateResult cap = CapabilityAnalyzer.analyze(manifest); // JSON: per-tool toxic-capability matrix
            all.addAll(po.findings);
            all.addAll(cap.findings);
            verdict = GateResult.worst(verdict, GateResult.worst(po.verdict, cap.verdict));
        }
        if (model != null) {
            GateResult m = analyzeModel(model);
            all.addAll(m.findings);
            verdict = GateResult.worst(verdict, m.verdict);
        }
        return new GateResult(verdict, all);
    }
}
