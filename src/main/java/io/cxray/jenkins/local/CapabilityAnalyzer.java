package io.cxray.jenkins.local;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * E22/M7 toxic-capability matrix (local) — parses a tools/list manifest, derives each tool's
 * declared capabilities from its name/description/schema, and flags a single tool that holds a
 * dangerous <em>combination</em> (worse than two separate single-capability tools). Java port of
 * {@code functions/agentBom.ts} (deriveCapabilities + TOXIC_PAIRS). Best-effort on parse: invalid
 * JSON yields no findings (the text-based poison scan still covers the manifest).
 */
public final class CapabilityAnalyzer {

    private CapabilityAnalyzer() {}

    private static final ObjectMapper M = new ObjectMapper();

    private static final Pattern FS_WRITE = Pattern.compile("\\b(write|create|delete|remove|unlink|mkdir|rmdir|save|edit|patch|append|overwrite|chmod|move|rename)\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern FS_READ = Pattern.compile("\\b(read|open|cat|list|glob|stat|load|scan|grep|find)\\b|\\bfile\\b|\\bpath\\b|\\bdirectory\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern NETWORK = Pattern.compile("\\b(http|https|url|uri|fetch|request|download|upload|webhook|api|endpoint|host|port|curl|wget|socket|dns)\\b|https?://", Pattern.CASE_INSENSITIVE);
    private static final Pattern PROC_EXEC = Pattern.compile("\\b(exec|run|shell|command|subprocess|spawn|bash|sh|eval|process|invoke)\\b|/bin/sh", Pattern.CASE_INSENSITIVE);
    private static final Pattern SECRETS = Pattern.compile("\\b(secret|token|password|credential|api[_-]?key|access[_-]?token|private\\s*key)\\b|\\.ssh|\\.env|id_rsa", Pattern.CASE_INSENSITIVE);

    static List<String> derive(String name, String desc, String schema) {
        String blob = (name == null ? "" : name) + "\n" + (desc == null ? "" : desc) + "\n" + (schema == null ? "" : schema);
        List<String> caps = new ArrayList<>();
        if (FS_WRITE.matcher(blob).find()) caps.add("filesystem-write");
        if (FS_READ.matcher(blob).find()) caps.add("filesystem-read");
        if (NETWORK.matcher(blob).find()) caps.add("network");
        if (PROC_EXEC.matcher(blob).find()) caps.add("process-exec");
        if (SECRETS.matcher(blob).find()) caps.add("secrets");
        return caps;
    }

    static String toxic(List<String> c) {
        boolean exec = c.contains("process-exec"), net = c.contains("network"), sec = c.contains("secrets"), fsw = c.contains("filesystem-write");
        if ((exec && net) || (exec && sec) || (exec && fsw) || (fsw && sec)) return "critical";
        if ((net && sec) || (net && fsw)) return "high";
        return "none";
    }

    static String combo(List<String> c) {
        boolean exec = c.contains("process-exec"), net = c.contains("network"), sec = c.contains("secrets"), fsw = c.contains("filesystem-write");
        if (exec && net) return "remote code execution / C2";
        if (exec && sec) return "exec with credential access";
        if (exec && fsw) return "write-then-execute";
        if (fsw && sec) return "credential theft + persistence";
        if (net && sec) return "credential exfiltration";
        if (net && fsw) return "remote dropper (download + write)";
        return "";
    }

    public static GateResult analyze(String manifestJson) {
        List<Finding> f = new ArrayList<>();
        if (manifestJson == null) return new GateResult("pass", f);
        JsonNode root;
        try {
            root = M.readTree(manifestJson);
        } catch (Exception e) {
            return new GateResult("pass", f); // not JSON — poison scan covers it
        }
        JsonNode tools = root.isArray() ? root
                : firstNonNull(root.get("tools"), path(root, "capabilities", "tools"), path(root, "server", "tools"));
        if (tools == null || !tools.isArray()) return new GateResult("pass", f);

        int worst = -1;
        for (JsonNode t : tools) {
            if (t == null || !t.has("name")) continue;
            String name = t.get("name").asText("");
            String desc = t.hasNonNull("description") ? t.get("description").asText("") : "";
            JsonNode schemaNode = firstNonNull(t.get("inputSchema"), t.get("parameters"), t.get("input_schema"));
            String schema = schemaNode == null ? "{}" : schemaNode.toString();
            List<String> caps = derive(name, desc, schema);
            String tox = toxic(caps);
            if (!"none".equals(tox)) {
                f.add(new Finding("capability", tox, name, "toxic combo: " + combo(caps) + " (" + String.join("+", caps) + ")", 0));
                worst = Math.max(worst, "critical".equals(tox) ? 2 : 1);
            }
        }
        String verdict = worst >= 2 ? "fail" : worst >= 1 ? "review" : "pass";
        return new GateResult(verdict, f);
    }

    private static JsonNode firstNonNull(JsonNode... nodes) {
        for (JsonNode n : nodes) if (n != null && !n.isNull()) return n;
        return null;
    }

    private static JsonNode path(JsonNode root, String a, String b) {
        JsonNode x = root.get(a);
        return x == null ? null : x.get(b);
    }
}
