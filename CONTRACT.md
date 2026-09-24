# `@darkmoon/client` — FROZEN contract (v1.0.0)

This is the single interface the **5 official Darkmoon integrations** build against,
in parallel, in isolated directories:

1. GitHub Actions
2. GitLab CI/CD
3. Jenkins (shared library / plugin, via the `darkmoon-ci` bin)
4. VS Code extension
5. JetBrains plugin (Kotlin — reuses the conformance fixtures/goldens, not this JS)

**Freeze rule:** the method signatures and the canonical enum value sets below are
frozen for the `1.x` line. Additive fields are allowed; breaking changes bump the
major and `CONTRACT_VERSION`. Everything is exported from the package root
(`@darkmoon/client`). Nothing else is part of the contract.

`export const CONTRACT_VERSION = "1.0.0"`.

---

## 1. Construct

```ts
import { DarkmoonClient } from "@darkmoon/client";

const client = new DarkmoonClient({
  mode: "auto",            // "auto" | "oss" | "pro"
  pro: {                   // used when mode is "pro" or "auto"
    baseUrl: "http://host:8000",   // with or without /api/v1
    username, password,            // OR token
    token,                         // pre-obtained JWT
    refuseInsecureDefault: true,   // refuse if admin still has default password
    timeoutMs: 15000,
  },
  oss: {                   // used when mode is "oss" or "auto"
    dataDir: "/path/darkmoon-settings",   // contains campaigns/ + vulnerabilities/
    reportsDir: "/path/reports",          // pentest_report_*.md
    scriptPath: "/path/darkmoon.sh",      // default ~/darkmoon.sh
    launchTemplate: ["docker","exec","opencode","opencode","run","{PROMPT}"], // optional
  },
});
```

In `auto` mode the client prefers Pro if reachable, else OSS. `detect()` caches.

## 2. The frozen surface (`DarkmoonClientContract`)

```ts
detect(): Promise<Capabilities>;
launchCampaign(input: LaunchInput): Promise<LaunchResult>;
getCampaignStatus(ref: CampaignRef): Promise<Campaign>;
listCampaigns(filter?: CampaignFilter): Promise<Campaign[]>;
getCampaign(id: CampaignRef): Promise<Campaign>;
listFindings(filter: FindingFilter, opts?: FindingReadOptions): Promise<Finding[]>;
getFinding(id: string, opts?: FindingReadOptions): Promise<Finding>;
getSeveritySummary(campaign: CampaignRef): Promise<SeveritySummary>;
getReport(campaign: CampaignRef, opts?: ReportOptions): Promise<Report>;
waitForCompletion(ref: CampaignRef, opts?: WaitOptions): Promise<Campaign>;
streamProgress(ref: CampaignRef): AsyncIterable<ProgressEvent>;
```

`CampaignRef = string | CorrelationHandle | LaunchResult` — pass an id, or the
handle/result returned by `launchCampaign`. The correlation handle is opaque; do
not read its fields.

### Canonical enums (frozen, lowercase)

- `Severity`   = `critical | high | medium | low | info`
- `FindingStatus` = `exploited | confirmed | unconfirmed | remediated`
- `CampaignStatus` = `queued | running | completed | stopped | failed | unknown`

Every backend value is normalized into these sets; unknown severities normalize
to `info` (never silently escalated).

### Key objects (fields the integrations may rely on)

```ts
interface Capabilities { edition; mode; version; available; features; detectedBy; warnings; }
interface SeveritySummary { critical; high; medium; low; info; total; }
interface Campaign { id; projectId; targetId; sessionId; target; status; overallRisk;
  createdAt; durationSeconds; reportPath; isSubagent; severity; executiveSummary; edition; }
interface Finding { id; campaignId; projectId; targetId; title; severity; status; category;
  cve; cvssScore; cvssVector; mitreAttackId; mitreAttackName; endpoint; description;
  remediation; discoveredByAgent; discoveredAt; evidence; edition; }
interface Report { campaignId; format; content; ready; redacted; }
```

`Campaign.raw` / `Finding.raw` carry the backend's raw object. **Do not log,
serialize, or emit `raw` to CI output** — it may contain rehydrated real values.

## 3. Safety contract (integrations MUST honor)

- **Redaction-safe by default.** `getReport()` returns a redacted body (evidence
  blocks blanked, secrets scrubbed). `listFindings()`/`getFinding()` return
  `evidence: null` unless `includeEvidence: true`, and then it is redacted.
- **Two-key opt-in for real values.** The un-redacted report needs
  `getReport(ref, { full: true, private: true })`; un-redacted evidence needs
  `{ includeEvidence: true, full: true, private: true }`. Passing `full` without
  `private` throws — this is deliberate friction, internal use only.
- **Never log secrets.** The client never returns/logs licenses, JWTs, LLM keys,
  credentials, or evidence. Use `scrubSecrets()` on anything you log yourself.
- **Insecure default.** If the Pro admin still has `must_change_password` /
  default secret, the Pro backend throws `InsecureDefaultError` (unless
  `refuseInsecureDefault: false`, which downgrades it to a `Capabilities.warning`).
- **Pass/fail is computed from findings, never from an exit code.** Use
  `computeFailPolicy(findingsOrSummary, "critical,high")`. The OSS CLI exits 0 even
  with criticals; the client ignores exit codes entirely.
- **Hard timeout = failure.** `waitForCompletion` treats a campaign still
  `running`/`unknown` past `timeoutMs` as `StuckCampaignError`, never a pass.
- **OSS concurrency.** OSS runs share one data dir; the client correlates the new
  campaign by snapshot-diff + session-id + mtime and **warns on collision**. Run
  **one container / compose-project per CI job** to avoid mis-attribution.

## 4. Errors (branch on `.code`, not message)

`DarkmoonError` base with `.code`. Subclasses: `DarkmoonNotAvailable`,
`AuthError`, `LicenseError`, `EditionMismatch`, `UnsupportedVersion`,
`ReportNotReady`, `CampaignNotFound`, `FindingNotFound`, `CorrelationFailed`,
`TimeoutError`, `StuckCampaignError`, `NetworkError`, `SchemaInvalid`,
`InsecureDefaultError`, `NotSupported`.

## 5. How the 5 integrations link this package

Each integration builder works in its **own directory** and consumes this client
as a linkable package — never by importing source paths. Two supported methods:

### A. Tarball (recommended for isolated/parallel builds, CI-reproducible)

```bash
# once, in this repo:
cd /home/mehdi/darkmoon-client && npm run build && npm pack
# → produces darkmoon-client-0.1.0.tgz

# in each integration dir:
npm install /home/mehdi/darkmoon-client/darkmoon-client-0.1.0.tgz
```

### B. `file:` dependency (fast local iteration)

```jsonc
// integration/package.json
{ "dependencies": { "@darkmoon/client": "file:../darkmoon-client" } }
```

Then in any integration:

```ts
import { DarkmoonClient, computeFailPolicy, CONTRACT_VERSION } from "@darkmoon/client";
```

The **CLI** (`darkmoon-ci`) is the link method for Jenkins/GitLab shell steps:

```bash
npx darkmoon-ci run --target http://app:3000 --fail-on critical,high --json
# exit 0 pass · 2 fail-policy · 1 tool error
```

### Kotlin (JetBrains)

The Kotlin client does **not** import this JS. It re-implements the same
normalization and asserts against the shared goldens in
`fixtures/conformance/*.golden.json` (language-neutral JSON produced by
`scripts/gen-golden.mjs`). Same inputs → byte-identical normalized objects.

## 6. Conformance guarantee

`OssLocalBackend` and `ProHttpBackend` produce **identical** normalized
`Campaign` / `Finding` / `SeveritySummary` objects for the same underlying
campaign (proven in `test/conformance/`, and verified live against the real Pro
FastAPI). Integrations can therefore treat the two editions interchangeably.
