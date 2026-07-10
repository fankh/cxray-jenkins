package io.cxray.jenkins.local;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Turns findings into copy-paste-ready suppression stanzas — the developer-facing half of the
 * false-positive loop. CVE findings become an OpenVEX document ({@code .cxray/vex.json}); everything
 * else becomes {@code .cxray/policy.json} waivers. The developer marks the ones that are genuinely
 * non-exploitable and commits them, instead of hand-writing the syntax.
 */
public final class Suggestions {

    private Suggestions() {}

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** OpenVEX document with a {@code not_affected} statement per distinct CVE finding (empty when none). */
    public static String vex(List<Finding> findings) {
        ObjectNode root = MAPPER.createObjectNode();
        root.put("@context", "https://openvex.dev/ns/v0.2.0");
        ArrayNode statements = root.putArray("statements");
        Set<String> seen = new LinkedHashSet<>();
        for (Finding f : findings) {
            if (!"cve".equalsIgnoreCase(f.check) || f.title == null || !seen.add(f.title)) continue;
            ObjectNode st = statements.addObject();
            st.putObject("vulnerability").put("name", f.title);
            st.put("status", "not_affected");
            st.put("justification", "vulnerable_code_not_in_execute_path");
        }
        return pretty(root);
    }

    /** {@code .cxray/policy.json} waiver stanzas for the non-CVE findings (empty when none). */
    public static String waivers(List<Finding> findings) {
        ObjectNode root = MAPPER.createObjectNode();
        ArrayNode arr = root.putArray("waivers");
        Set<String> seen = new LinkedHashSet<>();
        for (Finding f : findings) {
            if ("cve".equalsIgnoreCase(f.check)) continue; // CVEs go through VEX
            String key = f.check + "|" + f.title;
            if (!seen.add(key)) continue;
            ObjectNode w = arr.addObject();
            w.put("check", f.check);
            w.put("id", f.title == null ? "" : f.title);
            w.put("reason", "TODO: justify why this is acceptable");
            w.put("expires", "YYYY-MM-DD");
        }
        return pretty(root);
    }

    private static String pretty(Object node) {
        try {
            return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(node);
        } catch (IOException e) {
            return node.toString();
        }
    }
}
