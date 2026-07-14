# CXRay Security Gate — Roadmap & Product Backlog

**Status:** `v1.1.0` shipped — CI green, `cxray-jenkins.hpi` released, 76 tests + SpotBugs clean.
Two gate methods: **local** (offline, zero-dep) and **API** (scan-and-gate). 1.1.0 added compliance
mapping, policy-as-code + org-default inheritance, VEX, in-toto/SLSA attestation, SARIF, an MCP gate
in API mode, and Slack/Teams/webhook notifications (see [`../CHANGELOG.md`](../CHANGELOG.md)).

This document has two layers:

- **[Part 1 — Plugin roadmap](#part-1--plugin-roadmap)** — the plugin-scoped engineering tracks and
  the suggested sequence. Actionable, near-term.
- **[Part 2 — Product backlog](#part-2--product-backlog)** — the strategic layer across the whole
  CXRay platform (backend `cxray-main`, console `cxray-console`, and the CI gates: this Jenkins
  plugin + the `cxray-gate` GitHub Action/CLI) that feeds Part 1.

Tracks and themes are roughly independent; prune and re-tag freely.

---

# Part 1 — Plugin roadmap

## Track A — Adopt & prove in your Jenkins (now)

Local mode needs nothing but the `.hpi`; API mode needs a reachable CXRay + an access key.

- [ ] **A1. Install the plugin** — Manage Jenkins → Plugins → Advanced → Deploy Plugin →
  `cxray-jenkins.hpi` → restart. Confirm "CXRay Security Gate" appears in *Installed*.
- [ ] **A2. Smoke-test local mode (no backend)** — a job with `cxrayGate mode: 'local',
  modelFilePath: 'examples/Modelfile'` should **FAIL** with model-runtime findings; a clean
  `FROM llama3.2:3b` Modelfile should **PASS**. Confirms the build step, report tab, and gate wiring.
- [ ] **A3. Wire API mode** — mint an IP-bound access key for the Jenkins egress IP (see
  [`INTEGRATION.md`](INTEGRATION.md) §3), set the global API URL (admin-only), add the
  Username/password credential, then run `mode: 'api'` scan-and-gate against a real registry image.
  Confirm the poll → gate → report.
- [ ] **A4. Pin gate jobs to a stable-egress agent** so the IP-bound key keeps authenticating.

## Track B — API-mode reality check (blocks trusting API mode)

The backend gate endpoints the plugin calls **all exist** in `cxray-main`
(`/image/cve/gate/{id}`, `/ai/scan/{id}`, `/license/policy/{id}`, `/image/secrets/{id}`,
`POST /mcp/gate`, `POST /image/check/repo`, `GET /image/{id}` poll). The open risk is **not**
building them — it's confirming they're **deployed** and that their **real response shapes** match
the plugin's normalization (`../src/main/java/io/cxray/jenkins/api/CxrayApiGate.java`), which was
written against assumed/CLI shapes.

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
compiled plan (`../.claude/plans/compiled-twirling-church.md`) covers the console/backend side;
several pieces **directly power the plugin's API mode** (so Track B validates them from the CI angle):

- [ ] **D1. Confirm state of the parent plan's phases** — Phase 0 chart bug, Phase 1 agent risk
  depth (`/mcp/depth`), Phase 2 AI supply-chain (`/ai/scan` — powers the plugin's `aiGate`),
  Phase 3 CI gate + CVE gate (`/image/cve/gate` — powers the plugin's `cveGate`) + the
  `JwtAuthenticationFilter` access-key fallback. The controllers exist in the tree; verify shipped
  vs deployed and close any gaps.
- [ ] **D2. Align the plugin and the standalone `cxray-gate` CLI/Action** — both normalize the same
  gate endpoints; keep the mappings identical so CI results match across Jenkins and GitHub Actions.

## Suggested sequence

1. **A1 → A2** — prove local mode in your Jenkins this week (zero backend dependency, immediate value).
2. **B1 → B2** — confirm the gate endpoints are deployed and their shapes match; fix `CxrayApiGate`
   if needed. This is the gate to trusting API mode.
3. **A3 → B3** — wire and run one true end-to-end API scan-and-gate.
4. **C1** — add PR/commit feedback so blocked builds are actionable.
5. **D1** — reconcile the parent plan (deployed vs built) so the whole detect→measure→gate loop is real.
6. **C5 / D2** — decide public distribution + keep plugin/CLI normalization aligned.

## Reference
- Setup: [`INTEGRATION.md`](INTEGRATION.md) · Changes: [`../CHANGELOG.md`](../CHANGELOG.md)
- Normalization to validate: `../src/main/java/io/cxray/jenkins/api/CxrayApiGate.java`
- Backend controllers: `cxray-main` `controller/docker/CveGateController.java`,
  `controller/AiSupplyChainController.java`, `controller/LicensePolicyController.java`,
  `controller/docker/SecretsExposureController.java`
- Parent plan: `../.claude/plans/compiled-twirling-church.md`

---

# Part 2 — Product backlog

Product-level backlog across the whole CXRay platform. The plugin-scoped engineering tasks live in
[Part 1](#part-1--plugin-roadmap) above; this layer is the strategy that feeds it.

> Scope note: this backlog spans multiple repos. It lives here because that's where we're working;
> relocate to the product repo when convenient. IDs (`E#`, `T#`) are stable references.

> **Status (2026-07-11):** The parent plan (agent risk-depth `/mcp/depth`, AI supply-chain `/ai/scan`,
> CVE/secrets/MCP gates, JWT access-key fallback, gate-override audit, ProgressBar fix, capability
> matrix, AI Components, dashboard depth) is **implemented and shipped** — the risk-depth + durable
> posture surfaces (T2.1/T2.2) were **verified live on console-dev**. Since then the **offline
> agent-security gate suite** has been hardened across plugin + `cxray-gate` CLI (kept in
> normalization lock-step): indirect prompt-injection (OWASP-LLM01/ASI01), approved-MCP-server
> allowlist (ASI03), unsafe model (de)serialization → RCE (T1.3), and untrusted model provenance
> (T1.2) — plus policy inheritance carrying `mcpAllow` (T3.3), a pre-commit hook covering config +
> tool-manifest + Modelfile (T4.4), and GitLab/Azure CI templates (T4.2). Remaining: the **[Next]/
> [Later] product epics** below — they need specs/decisions and deploy the live app.

## 1. Product thesis — where we win

CXRay is an **AI-native DevSecOps gate**: one policy engine + CI/CD gate that covers **both** the
container/software supply chain **and** the agentic/LLM supply chain. That union is the wedge.

- **Container/software supply chain** — SBOM, EPSS, CISA-KEV, license policy, secrets. (Shipped.)
- **Agentic/AI supply chain** — MCP tool-integrity (pin/drift/poisoning), Agent-BOM (CycloneDX 1.6),
  toxic-capability matrix, OWASP-Agentic (ASI) gate, AI/model-artifact serialization risk. (Shipped/building.)
- **One gate, everywhere** — the same verdicts block a PR (GitHub Action) and a Jenkins build. (Shipped.)

**Competitive framing (guides prioritization, not a feature list):** container/cloud scanners
(Snyk, Wiz, Aqua, Prisma, Chainguard, Endor, Socket) are strong on images/deps but weak on *agentic*
security; AI-security point tools (Protect AI, Prompt Security, Lakera, HiddenLayer) cover models/prompts
but don't ship a DevSecOps *gate* with SBOM/KEV/license. CXRay's defensible middle is **agentic
supply-chain security expressed as a CI/CD policy gate** — plus a Korea supply-chain/SBOM compliance wedge.

## 2. Themes (epics)

Each theme lists concrete tasks. Tag = **[Now]** (this quarter), **[Next]** (next), **[Later]** (horizon).
Size = S/M/L. Prune and re-tag freely.

### E1 — AI/Model supply-chain detection *(detect)*
- [ ] **T1.1** [Now] S — Validate `/ai/scan` real response vs plugin/CLI normalization; lock a fixture. *(also roadmap B2)*
- [x] **T1.2** ✅ [Next] M — Model provenance: flag weights from file-sharing / unverifiable sources (dropbox/drive/gist/civitai/…) as `untrusted-provenance` in the offline model gate (plugin + CLI). *(remaining: surface source + license in reports)*
- [x] **T1.3** ✅ [Next] M — Unsafe-serialization coverage: pickle/`.pt`/`.pth`/joblib/`.h5` artifacts + `torch.load`/`pickle.load` calls → critical `unsafe-(de)serialization` with remediation, in the offline model gate (plugin + CLI).
- [x] **SBOM ingest** ✅ [Now] — `POST /image/check/sbom` in cxray-main (`SbomImporter` parses CycloneDX/SPDX → the same CVE matchers + persistence as the tar scan); backs the console's Import-SBOM tab. Air-gapped / SBOM-first analysis. *(CVE resolution needs OSS-Index egress the dev WAS lacks.)*
- [ ] **T1.4** [Later] L — Model card / dataset lineage capture into the Agent-BOM (data poisoning provenance).
- [x] **T1.5** ✅ [Later] M — "KEV for models": offline typosquat / namespace-confusion detection — a `FROM` model whose name is a one-char lookalike of a known family (llama/mistral/…) is flagged (plugin + CLI). *(remaining: a curated trojaned-weights denylist feed)*

### E2 — Agentic runtime & posture *(measure)*
- [x] **T2.1** ✅ [Now] M — Agent risk-depth surface (`/mcp/depth` + dashboard panel + `/mcp` matrix) — shipped; verified live on console-dev (servers/tools/toxic + ASI01/03/04 counts render with real data).
- [x] **T2.2** ✅ [Now] S — Durable per-pin posture rollup (identity/transport/capability) — shipped; verified live (dashboard "Agent security posture · durable rollup" panel).
- [x] **T2.3** ✅ [Next] M — MCP gate in CI (plugin + Action) — block on poisoning/drift/toxic-capability, not just container gates.
- [ ] **T2.4** [Next] M — Toxic-capability policy tuning: per-org allow/deny of capability pairs; justification workflow.
- [ ] **T2.5** [Later] L — Runtime/observed-behavior posture (what the agent *did*) vs declared Agent-BOM — declared-vs-actual diff.

### E3 — Policy-as-Code & governance
- [x] **T3.1** ✅ [Now] M — A single declarative policy file (repo-committed) the gate reads: thresholds, allow/deny lists, per-gate on/off, waivers. One source of truth for Jenkins + Action + console.
- [x] **T3.2** ✅ [Next] M — Waivers/exceptions with expiry + owner + reason; enforced centrally, audited (extend the gate-override audit).
- [x] **T3.3** ✅ [Next] S — Policy inheritance: org default → repo overrides (`Policy.layered()` — repo scalars win, waivers union, mcpAllow inherited). *(remaining: a distinct team tier)*
- [ ] **T3.4** [Later] M — "Policy simulation" / dry-run: show what *would* block before enforcing (adoption lever).

### E4 — Universal CI/CD gate (coverage)
- [x] **T4.1** ✅ [Now] S — Jenkins plugin: PR/commit status + human-readable "why blocked" (roadmap C1).
- [x] **T4.2** ✅ [Next] M — GitLab CI + Azure DevOps + **Bitbucket Pipelines** templates shipped (`tools/cxray-gate/ci/`); GitHub Action + Jenkins plugin cover the rest — full CI-platform parity.
- [ ] **T4.3** [Next] S — Container-native gate: an admission-webhook / `kubectl` mode reusing the same verdicts (shift-right).
- [x] **T4.4** ✅ [Later] M — Pre-commit hook for the offline checks (`tools/cxray-gate/hooks/` + installer) — auto-detects MCP config / tool manifest / Modelfile, honors `.cxray/policy.json`. *(remaining: an editor/IDE hook)*
- [x] **T4.5** ✅ [Now] S — Keep plugin + `cxray-gate` CLI normalization identical (shared contract test) — roadmap D2.

### E5 — Evidence, attestation & compliance
- [x] **T5.1** ✅ [Now] M — **Compliance mapping matrix** (see §3) — map every check to OWASP LLM/ASI, MITRE ATLAS, NIST AI RMF/SSDF, SLSA, EU CRA/AI Act, Korea SBOM. Surface the mapping in reports.
- [x] **T5.2** ✅ [Next] M — Gate evidence attestation: emit an in-toto Statement v1 (SLSA-style) per gated build — verdict + per-gate results + effective-policy digest + CI invocation. Shipped in the Jenkins plugin (`Attestation.java`) and the `cxray-gate` CLI/Action (`--attest`), same predicateType. *(remaining: signing is left to a cosign/in-toto step — by design)*
- [ ] **T5.3** [Next] M — SBOM export/ingest hardening: CycloneDX + SPDX in/out; VEX support to suppress non-exploitable CVEs.
- [ ] **T5.4** [Later] M — Compliance report pack (per release / per repo) mappable to an auditor's control list.

### E6 — Developer experience & remediation
- [x] **T6.1** ✅ [Now] S — Every finding ships a concrete fix + a copy-paste remediation (pin version, drop capability, convert model format).
- [ ] **T6.2** [Next] M — Auto-fix PRs where safe (bump to a non-vulnerable version, tighten an MCP manifest).
- [ ] **T6.3** [Next] S — False-positive feedback loop: one-click "not exploitable" → VEX + policy waiver.
- [ ] **T6.4** [Later] S — Noise budget: rank findings by exploitability (EPSS/KEV) so gates fail on what matters.

### E7 — Integrations & ecosystem
- [x] **T7.1** ✅ [Next] S — Notifications: Slack / Teams / email on gate FAIL with the report link.
- [ ] **T7.2** [Next] M — Ticketing: Jira / GitHub Issues auto-file on new critical findings.
- [ ] **T7.3** [Next] S — SIEM/SOAR: emit gate + posture events (webhook / syslog) — ties to the MxTac SOC console angle.
- [ ] **T7.4** [Later] M — Registry/artifact integrations (Harbor, ECR/GCR/ACR) for scan-on-push.

### E8 — Platform, scale, multi-tenancy
- [ ] **T8.1** [Next] M — Org/team RBAC for policy + waivers + audit (who can override a gate).
- [ ] **T8.2** [Next] M — Scan performance/caching: reuse image-id/scan results across pipeline stages and repos.
- [ ] **T8.3** [Later] L — Air-gapped/on-prem deployment profile (KEV/EPSS feed sync) — relevant to Korea enterprise/public sector.

### E9 — Metrics, reporting & exec view
- [ ] **T9.1** [Now] S — Instrument the KPIs in §4 (gate adoption, block/override rate, MTTR, coverage).
- [ ] **T9.2** [Next] M — Exec dashboard: supply-chain + agentic risk posture trend across the org.
- [ ] **T9.3** [Later] S — Benchmark view: your posture vs. anonymized cohort.

### E10 — GTM & packaging enablement
- [ ] **T10.1** [Now] S — 10-minute "first gate" quickstart (local mode, zero backend) — top-of-funnel.
- [ ] **T10.2** [Next] M — Reference architecture + demo repo showing a PR blocked on an agentic finding.
- [ ] **T10.3** [Next] S — Pricing/packaging hypotheses (per-pipeline / per-repo / per-agent) to validate.

## 3. Compliance & framework coverage (task set behind T5.1)

Target mapping — each becomes a coverage task; ✓ = plausibly covered today, ~ = partial, ○ = gap.

| Framework | Relevance | CXRay coverage (self-assess, then verify) |
|---|---|---|
| OWASP Top 10 for LLM Apps (2025) | LLM03 supply chain, LLM04 data/model poisoning, LLM07 insecure plugin/tool | ~ (MCP + model-artifact + Agent-BOM) |
| OWASP Agentic (ASI) | ASI01 tool poisoning, ASI03 excessive capability, ASI04 identity/authz | ~ (gate references ASI01/03/04) |
| MITRE ATLAS | ML supply-chain & model-serialization techniques | ○ → map findings to ATLAS IDs |
| NIST AI RMF (AI 100-1) | Govern/Map/Measure/Manage of AI risk | ○ → map posture to functions |
| NIST SSDF 800-218 / 218A | secure build + AI-specific practices | ~ (gate + SBOM) |
| SLSA | build provenance/attestation | ○ → T5.2 attestation |
| EU CRA / EU AI Act | SBOM obligation, high-risk AI controls | ~ (SBOM) → gap on attestation/reporting |
| US EO 14028 / Secure-by-Design | SBOM + attestation | ~ (SBOM export) |
| Korea SW 공급망 보안 가이드 / SBOM | domestic wedge | ~ → package a Korea compliance report |

Deliverable: a report badge per finding ("maps to ASI01 · OWASP LLM07 · ATLAS AML.T00xx") — turns raw
findings into audit-ready evidence and reinforces the differentiation.

## 4. Success metrics (product KPIs)

- **Adoption:** # pipelines with a CXRay gate; # repos/agents scanned; time-to-first-gate.
- **Efficacy:** gate block rate; % blocks that were true positives; MTTR from finding → fix.
- **Trust/friction:** override rate (and % audited with a reason); false-positive rate; noise budget adherence.
- **Coverage:** % of images with SBOM+KEV+license; % of agents with Agent-BOM + posture; framework-mapping coverage (§3).

## 5. Now / Next / Later snapshot

- **Now (prove value + close the loop):** T1.1, T2.1, T2.2, T3.1, T4.1, T4.5, T5.1, T6.1, T9.1, T10.1.
- **Next (differentiate + govern):** T2.3, T2.4, T3.2, T4.2, T5.2, T5.3, T6.2, T7.1–T7.3, T8.1, T9.2.
- **Later (moat + scale):** T1.4, T1.5, T2.5, T3.4, T4.3, T4.4, T5.4, T8.3, T9.3.

## 6. Non-goals / guardrails (for now)

- Not a runtime EDR/agent-firewall — we gate the *supply chain* and *declared posture*, not live traffic (revisit at T2.5).
- Not a general model-eval/red-team platform — leave prompt-injection eval to point tools; integrate, don't rebuild.
- Keep the **local (offline) gate dependency-free** — it's the adoption on-ramp; no server required.
- One normalization contract shared by Jenkins + Action + console — never fork gate logic per surface.
