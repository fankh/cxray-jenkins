package io.cxray.jenkins.local;

import java.util.List;

/** Aggregate result of a local gate run: an overall verdict plus the findings that produced it. */
public class GateResult {
    /** pass | review | fail */
    public final String verdict;
    public final List<Finding> findings;

    public GateResult(String verdict, List<Finding> findings) {
        this.verdict = verdict;
        this.findings = findings;
    }

    public static int rank(String verdict) {
        if ("fail".equals(verdict)) return 2;
        if ("review".equals(verdict)) return 1;
        return 0;
    }

    /** The more severe of two verdicts (pass &lt; review &lt; fail). */
    public static String worst(String a, String b) {
        return rank(b) > rank(a) ? b : a;
    }
}
