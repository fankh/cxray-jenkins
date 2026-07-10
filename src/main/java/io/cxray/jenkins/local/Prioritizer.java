package io.cxray.jenkins.local;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Orders findings by exploitability so the most actionable ones surface first in the report, log, and
 * attestation — a "noise budget": CISA-KEV (actively exploited) first, then by severity, then by CVSS
 * base. Ordering only; the verdict and the full finding set are unchanged (no silent truncation).
 */
public final class Prioritizer {

    private Prioritizer() {}

    private static final Pattern BASE = Pattern.compile("base\\s+([0-9]+(?:\\.[0-9]+)?)");

    /** A stably-sorted copy of {@code findings}, most-exploitable first. */
    public static List<Finding> byExploitability(List<Finding> findings) {
        List<Finding> sorted = new ArrayList<>(findings);
        sorted.sort((a, b) -> {
            int c = Integer.compare(kevRank(a), kevRank(b));
            if (c != 0) return c;
            c = Integer.compare(sevRank(a), sevRank(b));
            if (c != 0) return c;
            return Double.compare(base(b), base(a)); // higher CVSS first
        });
        return sorted;
    }

    private static int kevRank(Finding f) {
        String d = f.detail == null ? "" : f.detail.toUpperCase();
        return d.contains("KEV") ? 0 : 1;
    }

    private static int sevRank(Finding f) {
        String s = f.severity == null ? "" : f.severity.toLowerCase();
        switch (s) {
            case "critical": return 0;
            case "high": return 1;
            case "medium": return 2;
            case "low": return 3;
            default: return 4;
        }
    }

    private static double base(Finding f) {
        if (f.detail == null) return 0;
        Matcher m = BASE.matcher(f.detail);
        return m.find() ? Double.parseDouble(m.group(1)) : 0;
    }
}
