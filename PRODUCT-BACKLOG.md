# CXRay DevSecOps & AI-Security — Product Backlog (PM view)

Product-level backlog across the whole CXRay platform (backend `cxray-main`, console `cxray-console`,
and the CI gates: this Jenkins plugin + the `cxray-gate` GitHub Action/CLI). The plugin-scoped
engineering tasks live in [`ROADMAP.md`](ROADMAP.md); this file is the strategic layer that feeds it.

> Scope note: this backlog spans multiple repos. It lives here because that's where we're working;
> relocate to the product repo when convenient. IDs (`E#`, `T#`) are stable references.

---

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

---

## 2. Themes (epics)

Each theme lists concrete tasks. Tag = **[Now]** (this quarter), **[Next]** (next), **[Later]** (horizon).
Size = S/M/L. Prune and re-tag freely.

### E1 — AI/Model supply-chain detection *(detect)*
- [ ] **T1.1** [Now] S — Validate `/ai/scan` real response vs plugin/CLI normalization; lock a fixture. *(also ROADMAP B2)*
- [ ] **T1.2** [Next] M — Model provenance: flag models pulled from untrusted hubs / unsigned; surface source + license.
- [ ] **T1.3** [Next] M — Expand unsafe-serialization coverage (pickle/`torch.load`/joblib/keras-lambda) with a documented risk grade + remediation ("convert to safetensors/gguf").
- [ ] **T1.4** [Later] L — Model card / dataset lineage capture into the Agent-BOM (data poisoning provenance).
- [ ] **T1.5** [Later] M — Known-malicious-model feed (typosquat / trojaned weights) — a "KEV for models".

### E2 — Agentic runtime & posture *(measure)*
- [ ] **T2.1** [Now] M — Ship the agent risk-depth surface (`/mcp/depth` + dashboard + `/mcp` matrix) from the parent plan.
- [ ] **T2.2** [Now] S — Durable per-pin posture history (identity/transport/capability) trends over time — regression alerts on drift.
- [ ] **T2.3** [Next] M — MCP gate in CI (plugin + Action) — block on poisoning/drift/toxic-capability, not just container gates.
- [ ] **T2.4** [Next] M — Toxic-capability policy tuning: per-org allow/deny of capability pairs; justification workflow.
- [ ] **T2.5** [Later] L — Runtime/observed-behavior posture (what the agent *did*) vs declared Agent-BOM — declared-vs-actual diff.

### E3 — Policy-as-Code & governance
- [ ] **T3.1** [Now] M — A single declarative policy file (repo-committed) the gate reads: thresholds, allow/deny lists, per-gate on/off, waivers. One source of truth for Jenkins + Action + console.
- [ ] **T3.2** [Next] M — Waivers/exceptions with expiry + owner + reason; enforced centrally, audited (extend the gate-override audit).
- [ ] **T3.3** [Next] S — Policy inheritance: org default → team → repo overrides.
- [ ] **T3.4** [Later] M — "Policy simulation" / dry-run: show what *would* block before enforcing (adoption lever).

### E4 — Universal CI/CD gate (coverage)
- [ ] **T4.1** [Now] S — Jenkins plugin: PR/commit status + human-readable "why blocked" (ROADMAP C1).
- [ ] **T4.2** [Next] M — GitLab CI + Azure DevOps + Bitbucket templates (parity with the GitHub Action).
- [ ] **T4.3** [Next] S — Container-native gate: an admission-webhook / `kubectl` mode reusing the same verdicts (shift-right).
- [ ] **T4.4** [Later] M — Pre-commit / IDE hook for the local (offline) checks — earliest possible feedback.
- [ ] **T4.5** [Now] S — Keep plugin + `cxray-gate` CLI normalization identical (shared contract test) — ROADMAP D2.

### E5 — Evidence, attestation & compliance
- [ ] **T5.1** [Now] M — **Compliance mapping matrix** (see §3) — map every check to OWASP LLM/ASI, MITRE ATLAS, NIST AI RMF/SSDF, SLSA, EU CRA/AI Act, Korea SBOM. Surface the mapping in reports.
- [ ] **T5.2** [Next] M — Signed gate evidence: emit an in-toto/SLSA-style attestation per gated build (verdict + inputs + policy hash) for audit.
- [ ] **T5.3** [Next] M — SBOM export/ingest hardening: CycloneDX + SPDX in/out; VEX support to suppress non-exploitable CVEs.
- [ ] **T5.4** [Later] M — Compliance report pack (per release / per repo) mappable to an auditor's control list.

### E6 — Developer experience & remediation
- [ ] **T6.1** [Now] S — Every finding ships a concrete fix + a copy-paste remediation (pin version, drop capability, convert model format).
- [ ] **T6.2** [Next] M — Auto-fix PRs where safe (bump to a non-vulnerable version, tighten an MCP manifest).
- [ ] **T6.3** [Next] S — False-positive feedback loop: one-click "not exploitable" → VEX + policy waiver.
- [ ] **T6.4** [Later] S — Noise budget: rank findings by exploitability (EPSS/KEV) so gates fail on what matters.

### E7 — Integrations & ecosystem
- [ ] **T7.1** [Next] S — Notifications: Slack / Teams / email on gate FAIL with the report link.
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

---

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

---

## 4. Success metrics (product KPIs)

- **Adoption:** # pipelines with a CXRay gate; # repos/agents scanned; time-to-first-gate.
- **Efficacy:** gate block rate; % blocks that were true positives; MTTR from finding → fix.
- **Trust/friction:** override rate (and % audited with a reason); false-positive rate; noise budget adherence.
- **Coverage:** % of images with SBOM+KEV+license; % of agents with Agent-BOM + posture; framework-mapping coverage (§3).

---

## 5. Now / Next / Later snapshot

- **Now (prove value + close the loop):** T1.1, T2.1, T2.2, T3.1, T4.1, T4.5, T5.1, T6.1, T9.1, T10.1.
- **Next (differentiate + govern):** T2.3, T2.4, T3.2, T4.2, T5.2, T5.3, T6.2, T7.1–T7.3, T8.1, T9.2.
- **Later (moat + scale):** T1.4, T1.5, T2.5, T3.4, T4.3, T4.4, T5.4, T8.3, T9.3.

## 6. Non-goals / guardrails (for now)

- Not a runtime EDR/agent-firewall — we gate the *supply chain* and *declared posture*, not live traffic (revisit at T2.5).
- Not a general model-eval/red-team platform — leave prompt-injection eval to point tools; integrate, don't rebuild.
- Keep the **local (offline) gate dependency-free** — it's the adoption on-ramp; no server required.
- One normalization contract shared by Jenkins + Action + console — never fork gate logic per surface.
