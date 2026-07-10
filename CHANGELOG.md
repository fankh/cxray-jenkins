# Changelog

All notable changes to the CXRay Security Gate Jenkins plugin.

## [1.1.0] — 2026-07-10

Compliance, governance, and evidence features on top of 1.0.0.

### Added
- **Compliance mapping** — every finding maps to the frameworks it evidences (OWASP LLM Top 10,
  OWASP Agentic ASI, MITRE ATLAS, NIST SSDF, CISA-KEV/CWE) plus a concrete remediation; both show in
  the report.
- **Policy-as-code** — `.cxray/policy.json` (repo-committed): `failOn`/`gates`/`maxCvss`/`failOnKev`/
  `dryRun` override job config, and **waivers** (check+id, unexpired, audit reason) suppress findings.
- **Policy inheritance** — an admin **org default policy** (global config) is merged *under* each
  repo's policy: repo wins, org fills the gaps, waivers are the union.
- **VEX** — `.cxray/vex.json` (OpenVEX) drops CVE findings marked `not_affected`/`fixed`.
- **Attestation** — opt-in `attestationPath` writes an in-toto/SLSA Statement (verdict + inputs +
  SHA-256 policy digest) for cosign/in-toto to sign downstream.
- **SARIF 2.1.0** — opt-in `sarifPath` writes findings (with framework + remediation properties) for
  GitHub code scanning / Azure DevOps.
- **Exploitability ordering** — findings are ordered CISA-KEV → severity → CVSS everywhere.
- **Dry-run** — `dryRun` simulates: report/attestation/SARIF are written and "would block" is logged,
  but the build never fails (rollout lever).
- **Suppression suggestions** — the report shows copy-paste `.cxray/vex.json` + `.cxray/policy.json`
  waivers for the current findings (false-positive loop).
- **MCP gate in API mode** — `gates=…,mcp` gates a manifest via the authoritative `POST /mcp/gate`.
- **Notifications** — a global webhook (Slack/Teams/generic) is posted when the gate blocks a build.
- **Why-blocked** — the build description shows the verdict + severity tally.

### Tested
- 76 tests (from 38): compliance/VEX/policy/attestation/SARIF/prioritizer/suggestions units, the API
  contract test (locked to the real `cxray-main` gate shapes), the live HTTP wire path, and the
  JenkinsRule build/fail/dry-run/report flow. SpotBugs clean.

## [1.0.0] — 2026-07-10

Initial release.

### Added
- **Local (offline) gate** — analyzes MCP configs, tool manifests, and Ollama Modelfiles in the
  workspace with no server or credentials: transport & launch posture, identity & authorization
  posture, model-runtime supply-chain/exposure, tool-poisoning, and the per-tool toxic-capability
  matrix. Fails the build on policy violation.
- **CXRay API gate** — gates a scanned image against the CVE/KEV, license, secrets, and AI
  supply-chain policies (`GET /image/cve/gate` · `/license/policy` · `/image/secrets` · `/ai/scan`).
- **Scan-and-gate** — pull + scan a registry image (`POST /image/check/repo`), poll to completion,
  then gate. Optional registry credentials for private pulls.
- **Build report** — a persisted "CXRay Report" tab + a build-page summary, styled with the CXRay
  design tokens (severity as bold uppercase colored text).
- **Pipeline** — `cxrayGate(...)` step (Freestyle + declarative/scripted Pipeline) + Snippet
  Generator; Jenkins Credentials integration; global + per-job configuration.

### Security
- The CXRay API URL is **admin-only** (global config); the per-job override was removed to close an
  SSRF path that could redirect the access-key bearer to an attacker host.
- Credential-fill endpoints are permission-gated (`ADMINISTER` / `EXTENDED_READ`+`USE_ITEM`) so
  unprivileged users can't enumerate credential IDs.
- Workspace file reads reject absolute paths and `..` traversal.
- The global-config form warns when the API URL is `http://` (bearer would travel in cleartext).

### Tested
- 38 tests: local analyzers, API-gate normalization, the live `CxrayClient` HTTP wire path
  (in-JVM stub — bearer/body/poll/gates/redirect-as-auth-error), and JenkinsRule build/fail/report.
  SpotBugs clean.
