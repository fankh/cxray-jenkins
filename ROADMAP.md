# CXRay Security Gate — Roadmap & Next Tasks

**Status:** `v1.0.0` shipped (2026-07-10) — CI green, `cxray-jenkins.hpi` released, 38 tests +
SpotBugs clean. Two methods live: **local** (offline, zero deps) and **API** (scan-and-gate).

This document tracks what's next. Tracks are roughly independent; the **suggested sequence** at the
bottom orders them by dependency and value. Prune freely.

---

## Track A — Adopt & prove in your Jenkins (now)

Local mode needs nothing but the `.hpi`; API mode needs a reachable CXRay + an access key.

- [ ] **A1. Install the plugin** — Manage Jenkins → Plugins → Advanced → Deploy Plugin →
  `cxray-jenkins.hpi` → restart. Confirm "CXRay Security Gate" appears in *Installed*.
- [ ] **A2. Smoke-test local mode (no backend)** — a job with `cxrayGate mode: 'local',
  modelFilePath: 'examples/Modelfile'` should **FAIL** with model-runtime findings; a clean
  `FROM llama3.2:3b` Modelfile should **PASS**. Confirms the build step, report tab, and gate wiring.
- [ ] **A3. Wire API mode** — mint an IP-bound access key for the Jenkins egress IP (see
  `INTEGRATION.md` §3), set the global API URL (admin-only), add the Username/password credential,
  then run `mode: 'api'` scan-and-gate against a real registry image. Confirm the poll → gate → report.
- [ ] **A4. Pin gate jobs to a stable-egress agent** so the IP-bound key keeps authenticating.

## Track B — API-mode reality check (blocks trusting API mode)

The backend gate endpoints the plugin calls **all exist** in `cxray-main`
(`/image/cve/gate/{id}`, `/ai/scan/{id}`, `/license/policy/{id}`, `/image/secrets/{id}`,
`POST /mcp/gate`, `POST /image/check/repo`, `GET /image/{id}` poll). The open risk is **not**
building them — it's confirming they're **deployed** and that their **real response shapes** match
the plugin's normalization (`api/CxrayApiGate.java`), which was written against assumed/CLI shapes.

- [ ] **B1. Confirm the endpoints are deployed** on the CXRay instance Jenkins will call
  (API WAS / console proxy). Some may be built but not yet on the running server.
- [ ] **B2. Capture one real JSON response per endpoint** (curl with a valid bearer) and diff it
  against what `CxrayApiGate` reads — field names (`verdict`, `kev[].cveCode/base`, `deny`/`review`,
  `findings[].severity/kind/path/fileName`, `unsafeArtifactCount`), and the `data` wrapping on
  `check/repo` / `image/{id}`. Fix any mismatch in `CxrayApiGate` and add a fixture-backed test.
- [ ] **B3. One true end-to-end run** against a real image, all four gates enabled — replaces the
  in-JVM stub coverage with a live proof.

## Track C — Plugin maturity (near-term, after it's proven)

- [ ] **C1. PR/commit feedback** — surface the verdict as a build description / GitHub commit status
  so blocked PRs show *why* (not just a red build).
- [ ] **C2. MCP gate in API mode** — the plugin has `POST /mcp/gate` available server-side but API
  mode currently gates cve/license/secrets/ai; consider adding an MCP-manifest gate path.
- [ ] **C3. Field help + validation** — `help-*.html` for each config field; tighten `doCheck*`.
- [ ] **C4. Compat matrix** — verify against the min baseline (2.528.3) and the latest LTS.
- [ ] **C5. Optional — Jenkins Update Center** — requires the repo **public** + a jenkinsci hosting
  request (RPU) + `pom` metadata review. Only if we want public/one-click distribution; otherwise
  the release `.hpi` is enough for internal use.

## Track D — Broader AI-DevSecOps product (parent plan)

The plugin is one surface of the larger CXRay AI-DevSecOps loop (detect → measure → gate). The
compiled plan (`.claude/plans/compiled-twirling-church.md`) covers the console/backend side; several
pieces **directly power the plugin's API mode** (so Track B validates them from the CI angle):

- [ ] **D1. Confirm state of the parent plan's phases** — Phase 0 chart bug, Phase 1 agent risk
  depth (`/mcp/depth`), Phase 2 AI supply-chain (`/ai/scan` — powers the plugin's `aiGate`),
  Phase 3 CI gate + CVE gate (`/image/cve/gate` — powers the plugin's `cveGate`) + the
  `JwtAuthenticationFilter` access-key fallback. The controllers exist in the tree; verify shipped
  vs deployed and close any gaps.
- [ ] **D2. Align the plugin and the standalone `cxray-gate` CLI/Action** — both normalize the same
  gate endpoints; keep the mappings identical so CI results match across Jenkins and GitHub Actions.

---

## Suggested sequence

1. **A1 → A2** — prove local mode in your Jenkins this week (zero backend dependency, immediate value).
2. **B1 → B2** — confirm the gate endpoints are deployed and their shapes match; fix `CxrayApiGate`
   if needed. This is the gate to trusting API mode.
3. **A3 → B3** — wire and run one true end-to-end API scan-and-gate.
4. **C1** — add PR/commit feedback so blocked builds are actionable.
5. **D1** — reconcile the parent plan (deployed vs built) so the whole detect→measure→gate loop is real.
6. **C5 / D2** — decide public distribution + keep plugin/CLI normalization aligned.

## Reference
- Setup: [`INTEGRATION.md`](INTEGRATION.md) · Changes: [`CHANGELOG.md`](CHANGELOG.md)
- Normalization to validate: `src/main/java/io/cxray/jenkins/api/CxrayApiGate.java`
- Backend controllers: `cxray-main` `controller/docker/CveGateController.java`,
  `controller/AiSupplyChainController.java`, `controller/LicensePolicyController.java`,
  `controller/docker/SecretsExposureController.java`
- Parent plan: `.claude/plans/compiled-twirling-church.md`
