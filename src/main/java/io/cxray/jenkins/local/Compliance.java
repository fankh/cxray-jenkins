package io.cxray.jenkins.local;

/**
 * Maps a finding to the security frameworks it evidences and a concrete remediation. Turns raw
 * findings into audit-ready output (OWASP LLM Top 10, OWASP Agentic ASI, MITRE ATLAS) and gives the
 * developer a copy-paste fix. Pure static lookups keyed on the analyzer {@code check} (refined by
 * the finding title) so it stays unit-testable and dependency-free.
 */
public final class Compliance {

    private Compliance() {}

    /** Short " · "-joined framework references for a finding, e.g. "ASI01 · OWASP-LLM07 · ATLAS AML.T0010". */
    public static String frameworks(String check, String title) {
        String c = check == null ? "" : check.toLowerCase();
        switch (c) {
            case "poison":
                return "ASI01 (tool poisoning) · OWASP-LLM07 · ATLAS AML.T0051";
            case "capability":
            case "toxic":
                return "ASI03 (excessive capability) · OWASP-LLM08";
            case "identity":
                return "ASI04 (identity/authz) · OWASP-LLM06";
            case "transport":
                return "ASI04 · OWASP-LLM07 · ATLAS AML.T0049";
            case "model":
                return "OWASP-LLM03 (supply chain) · OWASP-LLM04 (poisoning) · ATLAS AML.T0010";
            case "ai":
                return "OWASP-LLM03 · OWASP-LLM04 · ATLAS AML.T0010";
            case "cve":
                return "OWASP-LLM03 (supply chain) · NIST-SSDF PW.4 · CISA-KEV";
            case "license":
                return "NIST-SSDF PS.3 · SW-supply-chain policy";
            case "secrets":
                return "OWASP-LLM06 · CWE-798 (hardcoded credentials)";
            default:
                return "SW-supply-chain policy";
        }
    }

    /** A concrete, copy-paste-oriented fix for a finding. */
    public static String remediation(String check, String title) {
        String c = check == null ? "" : check.toLowerCase();
        String t = title == null ? "" : title.toLowerCase();
        switch (c) {
            case "poison":
                return "Remove the injected instructions from the tool description and re-pin the manifest; treat tool text as untrusted data, not instructions.";
            case "capability":
            case "toxic":
                return "Split the tool so a single tool can't hold the toxic capability pair (e.g. exec+network); drop the capability it doesn't need.";
            case "identity":
                return "Require authentication/authorization on the server and scope tokens to least privilege; don't expose unauthenticated tools.";
            case "transport":
                return "Use stdio or authenticated HTTPS transport and bind to loopback — never 0.0.0.0/plaintext for a tool endpoint.";
            case "model":
                if (t.contains("unsafe") || t.contains("serial") || t.contains("pickle")) {
                    return "Convert the model to a safe format (safetensors/gguf); never load pickle/.pt/.h5 from an untrusted source.";
                }
                return "Pin the model to a trusted, versioned source; remove untrusted FROM/base references and re-scan.";
            case "ai":
                return "Replace unsafe-serialization model artifacts (pickle/.pt/.h5/.joblib) with safetensors/gguf/onnx; pin the model source.";
            case "cve":
                return "Upgrade the affected package to a fixed version; if it's a CISA-KEV CVE, patch immediately or remove the component.";
            case "license":
                return "Replace or remove the denied-license component, or record an approved exception with an owner and expiry.";
            case "secrets":
                return "Rotate the exposed secret now, remove it from the image layer/history, and inject it at runtime from a secret store.";
            default:
                return "Review the finding and bring the component into policy, or record an approved, expiring waiver.";
        }
    }
}
