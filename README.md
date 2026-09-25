# @darkmoon_ai/client

> **📦 Marketplace status:** Live on [npm](https://www.npmjs.com/package/@darkmoon_ai/client).

Cross-version client for **Darkmoon OSS (CLI)** and **Darkmoon Pro (REST)** — one frozen contract, both editions, redaction-safe by default.

![darkmoon-ci running against a synthetic Demo Shop lab (OSS mode)](https://raw.githubusercontent.com/ASCIT31/darkmoon-client/master/docs/screenshots/darkmoon-ci.png)

> `darkmoon-ci` OSS terminal output against a synthetic, authorized Demo Shop lab — findings are redaction-safe (evidence `null` by default).


## ⭐ Darkmoon ecosystem

Darkmoon is open-source — **a star really helps us grow.** [![Star the Darkmoon core](https://img.shields.io/github/stars/ASCIT31/Dark-Moon?style=social&label=Star%20Darkmoon)](https://github.com/ASCIT31/Dark-Moon)

🌐 **Website:** [dark-moon.org](https://dark-moon.org) · 📚 **Docs:** [docs.dark-moon.org](https://docs.dark-moon.org) · ⭐ **Star the core:** [github.com/ASCIT31/Dark-Moon](https://github.com/ASCIT31/Dark-Moon)

**Install the integrations, right where you work:**

| Platform | Get it |
|---|---|
| VS Code | [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=Darkmoon.darkmoon-vscode) |
| JetBrains | [JetBrains Marketplace](https://plugins.jetbrains.com/plugin/34497-darkmoon) |
| GitHub Actions | [GitHub Marketplace](https://github.com/marketplace/actions/darkmoon-pentest) |
| GitLab CI/CD | [CI/CD Catalog](https://gitlab.com/explore/catalog/Dark-Moon-X/darkmoon-scan) |
| Jenkins | [Download the .hpi](https://github.com/ASCIT31/darkmoon-jenkins/releases) |
| Client & CLI | [npm: @darkmoon_ai/client](https://www.npmjs.com/package/@darkmoon_ai/client) |


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

### v0.2.0 — integration surface (Splunk · Grafana · n8n)

Additive on top of the frozen v1 methods (`CONTRACT_VERSION` stays `1.0.0`):

```ts
// Triggers: webhooks (Pro) or a replayable event stream (Pro SSE / OSS poll)
const wh = await client.registerWebhook({ url: "https://splunk:8088/…", events: ["finding.exploited"] });
for await (const ev of client.streamEvents({ since: 0, events: ["campaign.completed"] })) { /* … */ }

// Retest → derived verdict {fixed|still_present|regressed|new}
const rt = await client.launchRetest({ campaignId });
const result = await client.getRetest(rt.retestId);       // result.verdictsSummary

// Redaction-safe evidence indicator + dashboard rollups
const meta = await client.getEvidenceMeta(findingId);      // counts only, never bodies
const ts   = await client.getTimeseries({ metric: "severity", group: "day" });
```

OSS degrades gracefully: webhooks throw `NOT_SUPPORTED` (no server), while retest,
evidence-meta, time-series and the event stream are computed client-side.

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
