# Integrating CXRay Security Gate into your Jenkins

End-to-end setup to run CXRay gates in your pipelines. The plugin has two methods — pick either or
both:

- **Local (offline)** — no CXRay server, no credentials. Gates MCP configs / tool manifests /
  Modelfiles in the workspace. **Fastest to adopt: skip straight to §6.**
- **CXRay API** — scan an image in CXRay (or gate one already scanned) for CVE/KEV, license,
  secrets, and AI supply-chain. Needs the CXRay API URL + an access key (§2–§4).

---

## 1. Prerequisites

| | Requirement |
|---|---|
| Jenkins | 2.528.3 or newer (the plugin's baseline) |
| Java (controller/agents) | 21 |
| Network (API mode only) | Jenkins must reach your CXRay console at `https://<console-host>/api` over HTTPS |
| Credentials plugin | present (bundled with Jenkins) |

## 2. Install the plugin

You have the built artifact: **`target/cxray-jenkins.hpi`**.

**Manage Jenkins → Plugins → Advanced settings → Deploy Plugin →** upload `cxray-jenkins.hpi` →
**Restart Jenkins** when prompted.

_(CLI alternative: copy the `.hpi` into `$JENKINS_HOME/plugins/` and restart.)_

Verify it loaded: *Manage Jenkins → Plugins → Installed* should list **CXRay Security Gate**.

## 3. (API mode) Get a CXRay access key

The gate authenticates with an **IP-bound access key** (username = access key, password = secret
key). The key is bound to the source IP the CXRay API sees for your Jenkins requests.

Ask your **CXRay administrator** to mint one for the Jenkins integration (this is the same one-time
bootstrap as the CXRay GitHub Action — see the console's `DEVSECOPS.md`):

1. Register the source IP the API will see (the Jenkins controller's egress IP, or your CXRay
   console proxy's IP if Jenkins calls the console `/api`):
   `POST /auth/register {"ipAddress":"<that-ip>","applicationName":"jenkins"}` (localhost-gated on the API host).
2. Mint the key **from that IP**: `POST /auth/accesskey/jenkins` → `{"accessKey":"…","secretKey":"…"}`.

Keep the pair — you'll store it as a Jenkins credential in §5.

> Pin your CXRay gate jobs to an agent with a **stable egress IP** so the IP-bound key keeps working.

## 4. (API mode) Set the CXRay API URL

**Manage Jenkins → System → CXRay**:
- **API URL** = your console origin + `/api`, e.g. `https://console.cxray.example/api`
- **Timeout (seconds)** = `30` (default)

Save.

## 5. (API mode) Add the credential

**Manage Jenkins → Credentials → System → Global → Add Credentials**:
- **Kind**: Username with password
- **Username**: the **access key** from §3
- **Password**: the **secret key** from §3
- **ID**: `cxray-access-key` (referenced by jobs)

_(Private registry pulls for scan-and-gate: add a second Username/password credential for the
registry and reference it as `registryCredentialsId`.)_

## 6. Configure a job

### Freestyle
Add build step **CXRay Security Gate**, choose the mode, fill the fields (§Reference), set **Fail
on** = `fail`.

### Pipeline — local (offline)

```groovy
stage('CXRay — local gate') {
  steps {
    cxrayGate mode: 'local',
              configPath: 'mcp/server.json',     // transport + identity
              manifestPath: 'mcp/tools.json',    // poisoning + toxic-capability
              modelFilePath: 'Modelfile',        // model runtime
              failOn: 'fail'
  }
}
```

### Pipeline — API scan-and-gate

```groovy
stage('CXRay — scan & gate') {
  steps {
    cxrayGate mode: 'api',
              repo: 'registry.cxray.example',    // or omit repo for docker.io
              image: 'my-service',
              tag: env.GIT_COMMIT,
              credentialsId: 'cxray-access-key',
              // registryCredentialsId: 'my-registry',   // private pulls
              gates: 'cve,license,secrets,ai',
              maxCvss: 9.0, failOnKev: true,
              pollTimeoutSec: 900,
              failOn: 'fail'
  }
}
```

### Pipeline — API gate an already-scanned image

```groovy
cxrayGate mode: 'api', imageId: env.CXRAY_IMAGE_ID,
          credentialsId: 'cxray-access-key', failOn: 'fail'
```

A ready-to-copy pipeline is in [`examples/Jenkinsfile`](examples/Jenkinsfile). Use the **Snippet
Generator** (Pipeline Syntax → `cxrayGate`) to build the step visually.

## 6b. (Optional) Policy-as-code — `.cxray/policy.json`

Commit a `.cxray/policy.json` to the repo and the gate reads it from the workspace; any field present
**overrides** the job config, so gate policy lives with the code and is honored identically in Jenkins
and the `cxray-gate` GitHub Action. Example in [`examples/policy.json`](examples/policy.json):

```json
{
  "failOn": "fail",
  "gates": ["cve", "license", "secrets", "ai"],
  "maxCvss": 9.0,
  "failOnKev": true,
  "waivers": [
    { "check": "cve", "id": "CVE-2024-0001", "reason": "not reachable; SEC-123", "expires": "2026-12-31" }
  ]
}
```

- **Overrides:** `failOn`, `gates`, `maxCvss`, `failOnKev` replace the job config when set.
- **Waivers:** an unexpired waiver whose `check` (and optional `id`, matched against a finding's title
  or detail) matches a finding **suppresses** it; the verdict is recomputed from what remains. Expired
  or unmatched waivers do nothing. `reason` is logged for audit. No policy file = job config unchanged.

## 7. Verify

Run the job. In the build:
- The **Console Output** shows `[CXRay] …` lines and the verdict.
- A **CXRay Report** link appears in the build's left menu (findings table).
- A **PASS/REVIEW/FAIL** summary shows on the build page.
- The build **fails** when the worst verdict is `FAIL` (or `REVIEW` with `failOn: 'review'`).

Quick smoke test (local mode, no server): point `modelFilePath` at `examples/Modelfile` — it should
**FAIL** with model-runtime findings; a clean `FROM llama3.2:3b` Modelfile should **PASS**.

## 8. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `auth failed … redirected to login` | The Jenkins source IP isn't registered with CXRay, or the key is for a different IP. Re-mint for the correct egress IP (§3). |
| `No API URL` | An admin must set it in *Manage Jenkins → System → CXRay* (it is intentionally not settable per job). |
| `Credentials not found` | The `credentialsId` doesn't match a Username/password credential visible to the job. |
| `Scan timed out` | Raise `pollTimeoutSec`, or check the image ref / registry credentials. |
| Build ERROR (not FAILURE) | A **misconfiguration** (missing inputs, unreachable API) — distinct from a security **FAILURE**. Fix the config. |
| Findings but build didn't fail | They were `REVIEW`-level; set `failOn: 'review'` to block on those too. |

## Reference — step parameters

| Param | Mode | Meaning |
|---|---|---|
| `mode` | both | `local` or `api` |
| `failOn` | both | `fail` (default) or `review` |
| `configPath` | local | mcp.json / server.json → transport + identity |
| `manifestPath` | local | tools/list manifest → poisoning + toxic-capability |
| `modelFilePath` | local | Ollama Modelfile / model-server config |
| `imageId` | api | gate an already-scanned image |
| `repo` / `image` / `tag` | api | registry image to scan-and-gate |
| `credentialsId` | api | CXRay access-key credential |
| `registryCredentialsId` | api | private-registry pull credential |
| `gates` | api | csv of `cve,license,secrets,ai,mcp` (`mcp` gates `manifestPath` via the authoritative OWASP-Agentic gate) |
| `maxCvss` / `failOnKev` | api | CVE gate thresholds (default 9.0 / true) |
| `pollTimeoutSec` / `pollIntervalSec` | api | scan poll (default 600 / 10) |

> The CXRay **API URL is admin-only** (Manage Jenkins → System). It is deliberately not a per-job
> parameter: a per-job override would let anyone who can configure a job redirect the access-key
> bearer to an arbitrary host and steal the credential (SSRF exfiltration).
