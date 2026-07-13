# CXRay Security Gate — Jenkins plugin

Fail a Jenkins build when your **AI agents** (or, via the CXRay API, your **container images**)
violate security policy. Two methods:

| | Method A — **CXRay API** | Method B — **Local (offline)** |
|---|---|---|
| Needs CXRay server + access key | ✅ | ❌ (no network, no credentials) |
| Container CVE/KEV · license · secrets · AI supply-chain · egress/packets | ✅ | ❌ (needs the backend scanner) |
| Agent/AI-security (poisoning · toxic-capability · transport · identity · model-runtime · prompt-injection · server-allowlist) | ✅ | ✅ (self-contained analyzers) |
| Inputs | image ref → scanned in CXRay | workspace files (mcp.json / server.json / Modelfile / tools manifest) |

**Both methods ship.** The plugin is a thin client — all policy comes from CXRay; it never
re-implements it.

## Status

- **P0 Scaffold** ✅ — Maven `hpi`, Jenkins 2.528.3 LTS + Java 21.
- **P1 Local gate** ✅ — offline analyzers (transport · identity · model-runtime · poisoning ·
  indirect prompt-injection · approved-server allowlist) + a Freestyle/Pipeline build step that fails
  the build on policy violation.
- **P2 API gate** ✅ — gate an already-scanned image via the CXRay API (CVE/KEV · license · secrets ·
  AI supply-chain), Jenkins Credentials + global config, IP-bound access-key bearer.
- **P3 Scan-and-gate** ✅ — give a registry image (`repo`/`image`/`tag`) and the plugin scans it
  (`POST /image/check/repo`), polls `GET /image/{id}` until `nowAnalyzing=false`, then gates.
  Optional registry credentials for private pulls.
- **P4 Build report** ✅ — a persisted "CXRay Report" tab (findings table) + a build-page summary,
  styled with the CXRay design tokens (severity as bold UPPERCASE colored text, not pill badges).
- **P5 Polish** ✅ — `cxrayGate(...)` pipeline symbol + Snippet Generator, the per-tool
  toxic-capability matrix (local), and `JenkinsRule` end-to-end tests.

The five build phases are complete; API mode has full in-JVM HTTP-wire test coverage.

### 1.1.0 — compliance, governance & evidence ✅
- **Compliance mapping** (OWASP LLM/ASI · MITRE ATLAS · NIST SSDF) + remediation on every finding.
- **Policy-as-code** (`.cxray/policy.json`) with waivers, plus admin **org-default policy inheritance**.
- **VEX** (`.cxray/vex.json`) suppression of non-exploitable CVEs.
- **in-toto/SLSA attestation** (`attestationPath`) and **SARIF 2.1.0** export (`sarifPath`).
- **Exploitability ordering** (KEV → severity → CVSS), **dry-run** simulation, copy-paste **suppression suggestions**.
- **MCP gate** in API mode; **Slack/Teams webhook** notifications.

Remaining follow-up: publishing to the Jenkins Update Center. See [`CHANGELOG.md`](CHANGELOG.md).

## Build & run

```bash
mvn hpi:run          # local Jenkins at http://localhost:8080/jenkins with the plugin loaded
mvn test             # run the analyzer unit tests
mvn -DskipTests package   # produce target/cxray-jenkins.hpi (install via Manage Plugins → Advanced)
```

> The parent POM + `jenkins.version` are a coordinated pair — bump both together to the current LTS
> if resolution complains.

## Examples

`examples/` has real inputs the local gate flags (verified: **FAIL, 12 findings**):
- `mcp-server.json` — unpinned `npx` launcher + inline static key (transport + identity)
- `tools.json` — a `run_query` tool holding exec+network (toxic-capability)
- `Modelfile` — http:// `FROM`, poisoned `SYSTEM`, `0.0.0.0` bind (model runtime)
- `Jenkinsfile` — a pipeline using `cxrayGate` (local gate + API scan-and-gate)

## Usage

### Freestyle
Add build step **"CXRay Security Gate (local)"** and set any of:
- **MCP server config** — path to `mcp.json` / `server.json` (transport + identity posture)
- **Tool manifest** — path to a `tools/list` manifest (poisoning scan)
- **Model file** — path to an Ollama `Modelfile` / model-server config (supply-chain + exposure)
- **Ingested content** — path to agent-ingested data / tool output (indirect prompt-injection scan)
- **MCP server id** — server identity checked against the `mcpAllow` allowlist in `.cxray/policy.json`
- **Fail on** — `fail` (default) or `review`

### Pipeline

```groovy
// clean symbol (Snippet Generator supported)
cxrayGate mode: 'local',
          configPath: 'mcp/server.json',
          manifestPath: 'mcp/tools.json',
          modelFilePath: 'Modelfile',
          contentPath: 'rag/retrieved.txt',
          mcpServerId: 'payments-mcp',
          failOn: 'fail'
```

The build **fails** when the worst verdict is `FAIL` (or `REVIEW` with `failOn=review`). A
misconfiguration (no inputs / missing files) reports an ERROR distinct from a security FAILURE.

### Method A — CXRay API (gate an already-scanned image)

1. **Global config** (Manage Jenkins → System → CXRay): set the API URL (console origin + `/api`).
2. **Credentials**: add a *Username/Password* credential — **username = access key**, **password =
   secret key**. The key is IP-bound, so register the Jenkins agent's egress IP with CXRay once (the
   same one-time bootstrap as the GitHub Action; see the console's `DEVSECOPS.md`).
3. In the step choose **CXRay API** mode and set the **Image ID**, credentials, and (optionally) the
   gate subset / `maxCvss` / `failOnKev`.

```groovy
// gate an already-scanned image
step([$class: 'CXRayGateStep', mode: 'api',
      imageId: env.CXRAY_IMAGE_ID, credentialsId: 'cxray-access-key',
      gates: 'cve,license,secrets,ai', maxCvss: 9.0, failOnKev: true, failOn: 'fail'])

// scan-and-gate: pull + scan the image you just built, then gate
step([$class: 'CXRayGateStep', mode: 'api',
      repo: 'registry.example.com', image: 'my-service', tag: env.GIT_COMMIT,
      credentialsId: 'cxray-access-key', registryCredentialsId: 'my-registry',
      pollTimeoutSec: 900, failOn: 'fail'])

// egress gate: fail on outbound flows to public IPs captured during behavioural (sandbox)
// analysis. Opt-in via gates="…,packet"; SKIPs (never a false pass) when no capture ran.
step([$class: 'CXRayGateStep', mode: 'api', imageId: env.CXRAY_IMAGE_ID,
      credentialsId: 'cxray-access-key', gates: 'cve,packet',
      failOnPublicEgress: true, allowPorts: '53', failOn: 'fail'])
```

The API gates are thin clients — they call `GET /image/cve/gate/{id}` · `/license/policy/{id}` ·
`/image/secrets/{id}` · `/ai/scan/{id}` · `/image/packet/gate/{id}` and never re-implement policy.
An auth/transport error is an ERROR (not a security FAILURE).

## What the local analyzers check

- **Transport & launch** (ASI04): unpinned `npx`/`uvx` fetch-and-exec launcher, plaintext `http://`
  transport, shell-exec surface, inline credentials.
- **Identity & authorization** (ASI03): long-lived static key, missing scoping/TTL, no pre-action
  authorization, no human-in-the-loop. Not-assessed (no auth signal) never falsely fails.
- **Model runtime** (E18.2/E18.3): untrusted/unpinned `FROM`, http:// pull, **untrusted provenance**
  (weights from a file-sharing host — dropbox/drive/gist/civitai/…), **typosquat / namespace-confusion**
  (a one-char lookalike of a known model family, e.g. `llamma` vs `llama`), poisoned baked-in `SYSTEM`
  prompt, `0.0.0.0` bind with no auth, inline secrets, and **unsafe serialization**
  (pickle/`.pt`/`.pth`/joblib/`.h5` artifacts or `torch.load`/`pickle.load` calls → RCE on load) — with line numbers.
- **Tool poisoning** (E19.1/E33.2): prompt-injection directives, hidden/bidi unicode, exfil phrasing.
- **Toxic-capability matrix** (E22/M7): a single tool holding a dangerous capability *combination*
  (exec+network, exec+secrets, network+secrets, …) — worse than two separate tools.
- **Indirect prompt-injection** (OWASP-LLM01/ASI01): scans agent-ingested data (retrieved docs, tool
  output) for override/role-hijack/covert directives, prompt-leak/exfil phrasing, credential bait, and
  hidden/bidi unicode — the untrusted-content path, distinct from the tool-description poisoning scan.
- **Approved-server allowlist** (ASI03): fails an MCP server not on the repo's `mcpAllow` allowlist
  (shadow AI), or one whose manifest hash drifts from the pinned `id=sha256` — governance at the gate.

Regexes are kept in sync with the CXRay console (`functions/*.ts`), the `cxray-gate` CLI
(`tools/cxray-gate/posture.mjs`), and the backend (`AgentPostureService.java`).
