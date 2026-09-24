# @darkmoon_ai/client


## ⭐ Star Darkmoon

Darkmoon is open-source and community-driven — **a star genuinely helps us.** If this is useful to you, please star:

[![Star the Darkmoon core](https://img.shields.io/github/stars/ASCIT31/Dark-Moon?style=social&label=Star%20the%20Darkmoon%20core)](https://github.com/ASCIT31/Dark-Moon)

And the ecosystem: [GitHub Action](https://github.com/ASCIT31/darkmoon-action) · [GitLab](https://github.com/ASCIT31/darkmoon-gitlab) · [Jenkins](https://github.com/ASCIT31/darkmoon-jenkins) · [VS Code](https://github.com/ASCIT31/darkmoon-vscode) · [JetBrains](https://github.com/ASCIT31/darkmoon-jetbrains) · [Client & CLI](https://github.com/ASCIT31/darkmoon-client)

Cross-version common client for **Darkmoon OSS** (CLI + JSON) and **Darkmoon Pro**
(REST API), behind one frozen interface. This is the **foundation** the 5 official
Darkmoon integrations (GitHub Actions, GitLab CI/CD, Jenkins, VS Code, JetBrains)
are built on top of.

- One interface, two backends: `OssLocalBackend` and `ProHttpBackend`.
- Capability detection with `mode: auto | oss | pro`.
- Canonical, normalized severity/status/campaign objects (identical across both
  editions — see the conformance suite).
- Strict secret hygiene: redaction-safe by default, real values only behind a
  deliberate two-key opt-in.
- A portable `darkmoon-ci` CLI with a findings-based fail policy for CI runners.
- Dual ESM/CJS build with TypeScript declarations.

See **[CONTRACT.md](./CONTRACT.md)** for the frozen API, the safety contract, and
how integrations link to this package.

## Install / build

```bash
npm install
npm run ci        # lint → typecheck → test → build
```

## Library usage

```ts
import { DarkmoonClient, computeFailPolicy } from "@darkmoon_ai/client";

const client = new DarkmoonClient({
  mode: "auto",
  pro: { baseUrl: "http://host:8000", username: "ci", password: process.env.DM_PASS },
  oss: { dataDir: "/data/darkmoon-settings", reportsDir: "/data/reports" },
});

const caps = await client.detect();                       // which edition + features
const launched = await client.launchCampaign({ target: "http://app:3000", focus: ["sqli"] });
const campaign = await client.waitForCompletion(launched, { timeoutMs: 30 * 60_000 });
const summary  = await client.getSeveritySummary(campaign.id);
const findings = await client.listFindings({ campaignId: campaign.id });
const verdict  = computeFailPolicy(findings, "critical,high");
if (verdict.failed) process.exit(verdict.exitCode);       // exit 2
```

## CLI (`darkmoon-ci`)

```bash
darkmoon-ci detect  --mode auto --pro-url http://host:8000
darkmoon-ci run     --target http://app:3000 --fail-on critical,high --json
darkmoon-ci summary <campaignId> --mode oss --oss-data-dir /data/darkmoon-settings
darkmoon-ci report  <campaignId> --out report.md          # redacted by default
```

Exit codes: `0` pass · `2` fail-policy tripped · `1` tool/usage error.
Backends configure via flags or env (`DARKMOON_PRO_URL`, `DARKMOON_PRO_USER`,
`DARKMOON_PRO_PASS`, `DARKMOON_PRO_TOKEN`, `DARKMOON_OSS_DATA_DIR`, …).

## Editions

| | OSS (`OssLocalBackend`) | Pro (`ProHttpBackend`) |
|---|---|---|
| Transport | reads the on-disk JSON tree, launches `darkmoon.sh` | `/api/v1` REST + JWT + SSE |
| Launch | `opencode run "TARGET: … PROGRAM=ci-<nonce>"` | `POST /run/campaign` |
| Correlation | snapshot-diff + session-id + mtime | `run_id`→campaign via session-id / diff |
| Progress | synthetic poll stream | live SSE `/run/{id}/stream` |
| Report not ready | missing/empty file | placeholder-200 → `ReportNotReady` |
| Dashboard / remediation / scheduler | no | yes (Pro only) |

The OSS CLI produces terminal/JSON + Markdown reports; the web dashboard and the
remediation→PR flow are **Pro only** and are never presented as open source.

## Layout

```
src/            library (contract, backends, normalize, redact, schema, fail-policy)
cli/            darkmoon-ci portable CLI
fixtures/       real captured campaigns/vulns + conformance goldens
test/           unit · integration · conformance (both backends) · fault injection
CONTRACT.md     the frozen API + link method for the 5 integrations
```

## Tests

Real OSS validation runs against the local WSL stack and an authorized lab
(Juice Shop). Pro validation runs against the real Front-API FastAPI locally and
a contract mock for fault injection. See `test/` and the delivery notes.
