# Changelog

All notable changes to the CXRay Security Gate Jenkins plugin.

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
