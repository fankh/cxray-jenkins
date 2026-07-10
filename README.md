# CXRay Security Gate — Jenkins plugin

Fail a Jenkins build when your **AI agents** (or, via the CXRay API, your **container images**)
violate security policy. Two methods:

| | Method A — **CXRay API** | Method B — **Local (offline)** |
|---|---|---|
| Needs CXRay server + access key | ✅ | ❌ (no network, no credentials) |
| Container CVE/KEV · license · secrets · AI supply-chain | ✅ | ❌ (needs the backend scanner) |
| Agent/AI-security (poisoning · toxic-capability · transport · identity · model-runtime) | ✅ | ✅ (self-contained analyzers) |
| Inputs | image ref → scanned in CXRay | workspace files (mcp.json / server.json / Modelfile / tools manifest) |

**This build ships Method B (local/offline).** Method A (scan-and-gate via the CXRay API) is on the
roadmap below. The plugin is a thin client — all policy comes from CXRay; it never re-implements it.

## Status

- **P0 Scaffold** ✅ — Maven `hpi`, Jenkins 2.462.x LTS + Java 17.
- **P1 Local gate** ✅ — offline analyzers (transport · identity · model-runtime · poisoning) + a
  Freestyle/Pipeline build step that fails the build on policy violation.
- **P2 API gate** ✅ — gate an already-scanned image via the CXRay API (CVE/KEV · license · secrets ·
  AI supply-chain), Jenkins Credentials + global config, IP-bound access-key bearer.
- **P3–P5** ⏳ — scan-and-gate loop (image ref → `check/repo` → poll), a styled build "CXRay Report"
  tab, `cxrayGate(...)` pipeline symbol + Snippet Generator, and the per-tool toxic-capability matrix.

## Build & run

```bash
mvn hpi:run          # local Jenkins at http://localhost:8080/jenkins with the plugin loaded
mvn test             # run the analyzer unit tests
mvn -DskipTests package   # produce target/cxray-jenkins.hpi (install via Manage Plugins → Advanced)
```

> The parent POM + `jenkins.version` are a coordinated pair — bump both together to the current LTS
> if resolution complains.

## Usage

### Freestyle
Add build step **"CXRay Security Gate (local)"** and set any of:
- **MCP server config** — path to `mcp.json` / `server.json` (transport + identity posture)
- **Tool manifest** — path to a `tools/list` manifest (poisoning scan)
- **Model file** — path to an Ollama `Modelfile` / model-server config (supply-chain + exposure)
- **Fail on** — `fail` (default) or `review`

### Pipeline

```groovy
// declarative / scripted — works via SimpleBuildStep
step([$class: 'CXRayGateStep',
      configPath: 'mcp/server.json',
      modelFilePath: 'Modelfile',
      failOn: 'fail'])
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
step([$class: 'CXRayGateStep', mode: 'api',
      imageId: env.CXRAY_IMAGE_ID, credentialsId: 'cxray-access-key',
      gates: 'cve,license,secrets,ai', maxCvss: 9.0, failOnKev: true, failOn: 'fail'])
```

The API gates are thin clients — they call `GET /image/cve/gate/{id}` · `/license/policy/{id}` ·
`/image/secrets/{id}` · `/ai/scan/{id}` and never re-implement policy. An auth/transport error is an
ERROR (not a security FAILURE).

## What the local analyzers check

- **Transport & launch** (ASI04): unpinned `npx`/`uvx` fetch-and-exec launcher, plaintext `http://`
  transport, shell-exec surface, inline credentials.
- **Identity & authorization** (ASI03): long-lived static key, missing scoping/TTL, no pre-action
  authorization, no human-in-the-loop. Not-assessed (no auth signal) never falsely fails.
- **Model runtime** (E18.2/E18.3): untrusted/unpinned `FROM`, http:// pull, poisoned baked-in
  `SYSTEM` prompt, `0.0.0.0` bind with no auth, inline secrets — with line numbers.
- **Tool poisoning** (E19.1/E33.2): prompt-injection directives, hidden/bidi unicode, exfil phrasing.

Regexes are kept in sync with the CXRay console (`functions/*.ts`), the `cxray-gate` CLI
(`tools/cxray-gate/posture.mjs`), and the backend (`AgentPostureService.java`).
