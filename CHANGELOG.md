# Changelog

All notable changes to the CXRay Security Gate Jenkins plugin.

## [1.0.0] — unreleased

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
