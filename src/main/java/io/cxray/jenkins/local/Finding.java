package io.cxray.jenkins.local;

/** One offline finding produced by a local analyzer. Immutable. */
public class Finding {
    /** which analyzer: transport | identity | model | poison */
    public final String check;
    /** critical | high | medium | low */
    public final String severity;
    public final String title;
    public final String detail;
    /** source line number, or 0 when not applicable */
    public final int line;

    public Finding(String check, String severity, String title, String detail, int line) {
        this.check = check;
        this.severity = severity;
        this.title = title;
        this.detail = detail;
        this.line = line;
    }
}
