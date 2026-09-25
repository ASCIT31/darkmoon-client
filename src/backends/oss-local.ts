import { promises as fs } from "node:fs";
import { existsSync } from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { spawn } from "node:child_process";
import { webcrypto } from "node:crypto";

import type {
  Campaign,
  CampaignFilter,
  Capabilities,
  CorrelationHandle,
  Finding,
  FindingFilter,
  FindingReadOptions,
  LaunchInput,
  LaunchResult,
  ProgressEvent,
} from "../contract.js";
import type { Backend, RawReport } from "./backend.js";
import { refToId } from "./backend.js";
import { Logger } from "../util/logger.js";
import { normalizeCampaign, normalizeFinding, matchesFindingFilter, severitySummaryFromFindings } from "../normalize.js";
import { parseCampaign, parseFindings } from "../schema.js";
import { CampaignNotFound, CorrelationFailed, DarkmoonNotAvailable, FindingNotFound, NotSupported } from "../errors.js";
import type {
  DarkmoonEvent,
  EvidenceMeta,
  EventStreamOptions,
  RetestInput,
  RetestLaunchResult,
  RetestResult,
  TimeseriesQuery,
  TimeseriesResult,
  WebhookInput,
  WebhookRegistration,
} from "../extensions.js";
import { computeRetestVerdicts, evidenceMetaFromFinding, summarizeVerdicts } from "../extensions-compute.js";

export interface OssLocalConfig {
  /** Data dir containing campaigns/ and vulnerabilities/ (host-side bind mount). */
  dataDir: string;
  /** Reports dir containing pentest_report_*.md. */
  reportsDir?: string;
  /** Path to darkmoon.sh (default: ~/darkmoon.sh). */
  scriptPath?: string;
  /** Working directory for the launch command. */
  cwd?: string;
  /**
   * Optional custom launch argv. Any element equal to "{PROMPT}" is replaced with
   * the built prompt string. When set, this REPLACES the darkmoon.sh invocation
   * (used e.g. for `docker exec opencode opencode run {PROMPT}`).
   */
  launchTemplate?: string[];
  logger?: Logger;
  timeoutMs?: number;
}

const RUNNING_STATUSES = new Set(["running", "queued", "unknown"]);

export class OssLocalBackend implements Backend {
  readonly edition = "oss" as const;
  private cfg: OssLocalConfig;
  private log: Logger;
  private campaignsDir: string;
  private vulnsDir: string;
  private reportsDir: string;
  private scriptPath: string;
  /** In-process retest tracking (OSS is stateless across runs; best-effort). */
  private retests = new Map<string, { baseCampaignId: string; targetId: string | null; correlation: CorrelationHandle; findingIds?: string[] }>();

  constructor(cfg: OssLocalConfig) {
    this.cfg = cfg;
    this.log = cfg.logger ?? new Logger("warn");
    this.campaignsDir = path.join(cfg.dataDir, "campaigns");
    this.vulnsDir = path.join(cfg.dataDir, "vulnerabilities");
    this.reportsDir = cfg.reportsDir ?? path.join(cfg.dataDir, "reports");
    this.scriptPath = cfg.scriptPath ?? path.join(os.homedir(), "darkmoon.sh");
  }

  async detect(): Promise<Capabilities> {
    const warnings: string[] = [];
    const hasData = existsSync(this.campaignsDir);
    if (!hasData) {
      throw new DarkmoonNotAvailable(`OSS data dir not found: ${this.campaignsDir}`, { dataDir: this.cfg.dataDir });
    }
    const hasScript = this.cfg.launchTemplate ? true : existsSync(this.scriptPath);
    if (!hasScript) {
      warnings.push(`darkmoon.sh not found at ${this.scriptPath}; read operations work, launchCampaign will fail.`);
    }
    // Best-effort version discovery: a VERSION file in the data dir, else unknown.
    let version = "unknown";
    for (const f of ["VERSION", "version.txt", ".darkmoon-version"]) {
      const p = path.join(this.cfg.dataDir, f);
      if (existsSync(p)) {
        try {
          version = (await fs.readFile(p, "utf8")).trim() || "unknown";
        } catch {
          /* ignore */
        }
        break;
      }
    }
    return {
      edition: "oss",
      mode: "oss",
      version,
      available: true,
      features: { restApi: false, streaming: false, auth: false, remediation: false, dashboard: false, scheduler: false },
      detectedBy: "cli-probe",
      warnings,
    };
  }

  private buildPrompt(input: LaunchInput, nonce: string): string {
    const parts = [`TARGET: ${input.target}`, `PROGRAM=${nonce}`];
    if (input.targets?.length) parts.push(`TARGETS=${input.targets.join(",")}`);
    if (input.outOfScope?.length) parts.push(`OUT=${input.outOfScope.join(",")}`);
    if (input.exclude?.length) parts.push(`EXCLUDE=${input.exclude.join(",")}`);
    if (input.focus?.length) parts.push(`FOCUS=${input.focus.join(",")}`);
    if (input.credentials?.length) parts.push(`CREDS=${input.credentials.join(",")}`);
    if (input.tokens?.length) parts.push(`TOKEN=${input.tokens.join(",")}`);
    if (input.noise) parts.push(`NOISE=${input.noise}`);
    if (input.severity) parts.push(`SEVERITY=${input.severity}`);
    if (input.format) parts.push(`FORMAT=${input.format}`);
    if (input.rules?.length) parts.push(`RULES="${input.rules.join(";")}"`);
    if (input.safeHarbor) parts.push(`SAFE_HARBOR=${input.safeHarbor}`);
    return parts.join(" ");
  }

  async launchCampaign(input: LaunchInput): Promise<LaunchResult> {
    const nonce = input.program ?? `ci-${randomHex(8)}`;
    const prompt = this.buildPrompt(input, nonce);
    const preCampaignIds = await this.listCampaignIds();

    let cmd: string;
    let args: string[];
    if (this.cfg.launchTemplate?.length) {
      const tpl = this.cfg.launchTemplate.map((a) => (a === "{PROMPT}" ? prompt : a));
      cmd = tpl[0]!;
      args = tpl.slice(1);
    } else {
      if (!existsSync(this.scriptPath)) {
        throw new DarkmoonNotAvailable(`darkmoon.sh not found at ${this.scriptPath}.`);
      }
      cmd = this.scriptPath;
      args = [prompt];
    }

    // Detached background launch — the campaign runs for minutes; we return a
    // handle immediately and correlate later against the campaigns/ snapshot.
    const child = spawn(cmd, args, {
      cwd: this.cfg.cwd ?? path.dirname(this.scriptPath),
      env: process.env,
      detached: true,
      stdio: "ignore",
    });
    child.unref();

    const correlation: CorrelationHandle = {
      edition: "oss",
      runId: null,
      campaignId: null,
      nonce,
      preCampaignIds,
      startedAtMs: Date.now(),
    };
    this.log.info(`OSS campaign launched (nonce=${nonce}, pid=${child.pid ?? "?"}). Correlation deferred.`);
    return { correlation, campaignId: null, runId: null };
  }

  private async listCampaignIds(): Promise<string[]> {
    try {
      const files = await fs.readdir(this.campaignsDir);
      return files.filter((f) => f.endsWith(".json")).map((f) => f.replace(/\.json$/, ""));
    } catch {
      return [];
    }
  }

  async resolveCampaignId(ref: CorrelationHandle | string): Promise<string | null> {
    const direct = refToId(ref);
    if (direct) return direct;
    if (typeof ref === "string") return ref;
    if (ref.campaignId) return ref.campaignId;

    const pre = new Set(ref.preCampaignIds ?? []);
    let files: string[];
    try {
      files = (await fs.readdir(this.campaignsDir)).filter((f) => f.endsWith(".json") && f !== "unknown.json");
    } catch {
      return null;
    }
    const fresh: Array<{ id: string; mtimeMs: number }> = [];
    for (const f of files) {
      const id = f.replace(/\.json$/, "");
      if (pre.has(id)) continue;
      try {
        const st = await fs.stat(path.join(this.campaignsDir, f));
        // Only consider campaigns created at/after launch (mtime tie-break).
        if (st.mtimeMs >= ref.startedAtMs - 2000) fresh.push({ id, mtimeMs: st.mtimeMs });
      } catch {
        /* ignore */
      }
    }
    if (fresh.length === 0) return null;
    if (fresh.length === 1) {
      ref.campaignId = fresh[0]!.id;
      return fresh[0]!.id;
    }
    // Multiple fresh campaigns → concurrent-run collision risk. Pick newest but flag.
    fresh.sort((a, b) => b.mtimeMs - a.mtimeMs);
    this.log.warn(
      `Multiple new campaigns since launch (${fresh.map((x) => x.id).join(", ")}). ` +
        `Concurrent OSS runs share one data dir — run one container/compose-project per job. Attributing to newest by mtime.`,
    );
    ref.campaignId = fresh[0]!.id;
    return fresh[0]!.id;
  }

  private async readCampaignFile(id: string): Promise<Record<string, unknown> | null> {
    const p = path.join(this.campaignsDir, `${id}.json`);
    if (!existsSync(p)) return null;
    try {
      return JSON.parse(await fs.readFile(p, "utf8"));
    } catch {
      return null;
    }
  }

  private async readFindingsFile(campaignId: string): Promise<any[]> {
    const p = path.join(this.vulnsDir, `${campaignId}.json`);
    if (!existsSync(p)) return [];
    try {
      return parseFindings(JSON.parse(await fs.readFile(p, "utf8")));
    } catch {
      return [];
    }
  }

  async getCampaign(id: string): Promise<Campaign> {
    const raw = await this.readCampaignFile(id);
    if (!raw) throw new CampaignNotFound(`Campaign ${id} not found in ${this.campaignsDir}.`, { id });
    const campaign = normalizeCampaign(parseCampaign(raw), "oss");
    // Findings are authoritative: recompute severity from the vulns file if present.
    const raws = await this.readFindingsFile(id);
    if (raws.length > 0) {
      const findings = raws.map((v) => normalizeFinding(v, "oss"));
      campaign.severity = severitySummaryFromFindings(findings);
    }
    return campaign;
  }

  async getCampaignStatus(ref: CorrelationHandle | string): Promise<Campaign> {
    const id = await this.resolveCampaignId(ref);
    if (!id) {
      // Not correlated yet: synthetic running campaign.
      return {
        id: typeof ref === "string" ? ref : `oss:pending:${ref.nonce ?? ""}`,
        projectId: null,
        targetId: null,
        sessionId: null,
        target: null,
        status: "running",
        overallRisk: "none",
        createdAt: null,
        durationSeconds: null,
        reportPath: null,
        isSubagent: false,
        severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
        executiveSummary: null,
        edition: "oss",
      };
    }
    return this.getCampaign(id);
  }

  async listCampaigns(filter?: CampaignFilter): Promise<Campaign[]> {
    let files: string[];
    try {
      files = (await fs.readdir(this.campaignsDir)).filter((f) => f.endsWith(".json") && f !== "unknown.json");
    } catch {
      return [];
    }
    const out: Campaign[] = [];
    for (const f of files) {
      const raw = await this.readCampaignFile(f.replace(/\.json$/, ""));
      if (!raw) continue;
      if (raw.is_subagent) continue; // exclude sub-agent artefacts, like the Pro API
      const c = normalizeCampaign(parseCampaign(raw), "oss");
      if (filter?.targetId && c.targetId !== filter.targetId) continue;
      if (filter?.status && c.status !== filter.status) continue;
      out.push(c);
    }
    return out;
  }

  async listFindings(filter: FindingFilter, opts?: FindingReadOptions): Promise<Finding[]> {
    let campaignIds: string[];
    if (filter.campaignId) {
      campaignIds = [filter.campaignId];
    } else {
      try {
        campaignIds = (await fs.readdir(this.vulnsDir)).filter((f) => f.endsWith(".json")).map((f) => f.replace(/\.json$/, ""));
      } catch {
        campaignIds = [];
      }
    }
    const out: Finding[] = [];
    for (const cid of campaignIds) {
      const raws = await this.readFindingsFile(cid);
      for (const v of raws) {
        const f = normalizeFinding(v, "oss", { includeEvidence: opts?.includeEvidence, full: opts?.full });
        if (matchesFindingFilter(f, filter)) out.push(f);
      }
    }
    return out;
  }

  async getFinding(id: string, opts?: FindingReadOptions): Promise<Finding> {
    let files: string[];
    try {
      files = (await fs.readdir(this.vulnsDir)).filter((f) => f.endsWith(".json"));
    } catch {
      files = [];
    }
    for (const f of files) {
      const raws = await this.readFindingsFile(f.replace(/\.json$/, ""));
      const hit = raws.find((v: any) => String(v.id ?? v.node_id ?? "") === id);
      if (hit) return normalizeFinding(hit, "oss", { includeEvidence: opts?.includeEvidence, full: opts?.full });
    }
    throw new FindingNotFound(`Finding ${id} not found.`, { id });
  }

  /** Map a container report_path (/reports/x.md) to the host reports dir. */
  private resolveReportPath(reportPath: string | null): string | null {
    if (!reportPath) return null;
    const base = path.basename(reportPath);
    const candidate = path.join(this.reportsDir, base);
    if (existsSync(candidate)) return candidate;
    if (existsSync(reportPath)) return reportPath;
    return null;
  }

  private async newestReport(): Promise<string | null> {
    try {
      const files = (await fs.readdir(this.reportsDir)).filter((f) => f.endsWith(".md"));
      let newest: { p: string; mtimeMs: number } | null = null;
      for (const f of files) {
        const p = path.join(this.reportsDir, f);
        const st = await fs.stat(p);
        if (!newest || st.mtimeMs > newest.mtimeMs) newest = { p, mtimeMs: st.mtimeMs };
      }
      return newest?.p ?? null;
    } catch {
      return null;
    }
  }

  async getReport(campaignId: string): Promise<RawReport> {
    const raw = await this.readCampaignFile(campaignId);
    if (!raw) throw new CampaignNotFound(`Campaign ${campaignId} not found.`, { id: campaignId });
    let file = this.resolveReportPath((raw.report_path as string) ?? null);
    if (!file) file = await this.newestReport();
    if (!file) {
      return { campaignId, format: "markdown", content: "", ready: false };
    }
    const content = await fs.readFile(file, "utf8");
    const ready = content.trim().length > 0;
    return { campaignId, format: "markdown", content, ready };
  }

  /**
   * OSS has no live event stream. We emit a synthetic poll-based progress stream:
   * poll the campaign status until it reaches a terminal state.
   */
  async *streamProgress(ref: CorrelationHandle | string): AsyncIterable<ProgressEvent> {
    const pollMs = 5000;
    let lastStatus = "";
    for (;;) {
      let campaign: Campaign | null = null;
      try {
        campaign = await this.getCampaignStatus(ref);
      } catch {
        campaign = null;
      }
      const status = campaign?.status ?? "running";
      if (status !== lastStatus) {
        lastStatus = status;
        yield {
          type: "status",
          campaignId: campaign?.id ?? null,
          message: `campaign status: ${status}`,
          terminal: !RUNNING_STATUSES.has(status),
          raw: { status },
        };
      }
      if (campaign && !RUNNING_STATUSES.has(status)) return;
      await sleep(pollMs);
    }
  }

  // ── v0.2.0 additive surface (graceful OSS degradation) ──────────────────

  // OSS ships NO API server, so outbound webhooks cannot be dispatched. We fail
  // loudly with NOT_SUPPORTED rather than pretend — integrations branch on the
  // code and fall back to the polling event stream below.
  async registerWebhook(_input: WebhookInput): Promise<WebhookRegistration> {
    throw new NotSupported("Webhooks require Darkmoon Pro (OSS runs no server). Use streamEvents() polling instead.");
  }
  async listWebhooks(): Promise<WebhookRegistration[]> {
    throw new NotSupported("Webhooks require Darkmoon Pro (OSS runs no server).");
  }
  async deleteWebhook(_id: string): Promise<boolean> {
    throw new NotSupported("Webhooks require Darkmoon Pro (OSS runs no server).");
  }

  /** OSS retest = launch a fresh campaign on the base scope; verdict computed client-side. */
  async launchRetest(input: RetestInput): Promise<RetestLaunchResult> {
    let baseCampaignId = input.campaignId ?? null;
    let targetId: string | null = null;
    let targetHost: string | null = null;

    if (baseCampaignId) {
      const base = await this.getCampaign(baseCampaignId);
      targetId = base.targetId;
      targetHost = base.target;
    } else if (input.targetId) {
      const campaigns = (await this.listCampaigns({ targetId: input.targetId }))
        .sort((a, b) => String(a.createdAt ?? "").localeCompare(String(b.createdAt ?? "")));
      const base = campaigns[campaigns.length - 1];
      if (!base) throw new CampaignNotFound(`No prior campaign for target ${input.targetId}.`);
      baseCampaignId = base.id;
      targetId = base.targetId;
      targetHost = base.target;
    } else {
      throw new NotSupported("launchRetest requires targetId or campaignId.");
    }

    if (!targetHost) throw new CampaignNotFound("Cannot resolve target host to retest.");

    const launched = await this.launchCampaign({ target: targetHost, safeHarbor: input.safeHarbor ?? "non-destructive" });
    const retestId = `retest_${randomHex(8)}`;
    this.retests.set(retestId, {
      baseCampaignId: baseCampaignId!,
      targetId,
      correlation: launched.correlation,
      findingIds: input.findingIds,
    });
    return { retestId, runId: launched.runId, baseCampaignId, targetId };
  }

  async getRetest(id: string): Promise<RetestResult> {
    const rec = this.retests.get(id);
    if (!rec) throw new NotSupported(`Retest ${id} is not tracked in this process (OSS retests are in-memory).`);
    const newCampaignId = await this.resolveCampaignId(rec.correlation);
    let status: "running" | "completed" = "running";
    let findings = [] as ReturnType<typeof computeRetestVerdicts>;
    if (newCampaignId) {
      const newCampaign = await this.getCampaign(newCampaignId).catch(() => null);
      if (newCampaign && !RUNNING_STATUSES.has(newCampaign.status)) status = "completed";
      const base = await this.listFindings({ campaignId: rec.baseCampaignId }, { includeEvidence: false });
      const next = await this.listFindings({ campaignId: newCampaignId }, { includeEvidence: false });
      findings = computeRetestVerdicts(base, next, rec.findingIds);
    }
    return {
      retestId: id,
      baseCampaignId: rec.baseCampaignId,
      newCampaignId,
      targetId: rec.targetId,
      runId: rec.correlation.runId,
      status,
      verdictsSummary: summarizeVerdicts(findings),
      findings,
      edition: "oss",
    };
  }

  async getEvidenceMeta(id: string): Promise<EvidenceMeta> {
    // Fetch the finding WITH (redacted) evidence, then derive counts only.
    const finding = await this.getFinding(id, { includeEvidence: true }).catch(() => null);
    if (!finding) throw new FindingNotFound(`Finding ${id} not found.`, { id });
    return evidenceMetaFromFinding(id, finding);
  }

  async getTimeseries(query: TimeseriesQuery = {}): Promise<TimeseriesResult> {
    const metric = query.metric ?? "severity";
    const group = query.group ?? "day";
    let campaigns = await this.listCampaigns();
    if (query.projectId) campaigns = campaigns.filter((c) => c.projectId === query.projectId);
    if (query.targetId) campaigns = campaigns.filter((c) => c.targetId === query.targetId);
    if (query.from) campaigns = campaigns.filter((c) => String(c.createdAt ?? "").slice(0, 10) >= query.from!);
    if (query.to) campaigns = campaigns.filter((c) => String(c.createdAt ?? "").slice(0, 10) <= query.to!);
    campaigns.sort((a, b) => String(a.createdAt ?? "").localeCompare(String(b.createdAt ?? "")));

    const buckets: string[] = [];
    const grid = new Map<string, Map<string, number>>();
    const keys: string[] = [];
    const add = (b: string, key: string) => {
      if (!grid.has(b)) { grid.set(b, new Map()); buckets.push(b); }
      const row = grid.get(b)!;
      row.set(key, (row.get(key) ?? 0) + 1);
      if (!keys.includes(key)) keys.push(key);
    };
    for (const c of campaigns) {
      const b = group === "campaign" ? c.id : String(c.createdAt ?? "").slice(0, 10) || "unknown";
      if (metric === "campaigns") { add(b, "campaigns"); continue; }
      const fs = await this.listFindings({ campaignId: c.id }, { includeEvidence: false });
      for (const f of fs) {
        const value = metric === "severity" ? f.severity : metric === "status" ? f.status : (f.category ?? "unknown");
        add(b, String(value ?? "unknown").toLowerCase());
      }
    }
    return {
      metric, group, edition: "oss",
      series: keys.map((key) => ({ key, points: buckets.map((b) => ({ t: b, value: grid.get(b)?.get(key) ?? 0 })) })),
    };
  }

  /**
   * OSS has no event bus. We synthesize the same event taxonomy by polling the
   * data dir and diffing campaigns/findings, so a trigger works identically
   * (graceful degradation). Yields until the AbortSignal fires.
   */
  async *streamEvents(opts: EventStreamOptions = {}): AsyncIterable<DarkmoonEvent> {
    const pollMs = opts.pollIntervalMs ?? 5000;
    const wanted = opts.events?.length ? new Set(opts.events) : null;
    let seq = opts.since ?? 0;
    const seenCampaign = new Map<string, string>();      // id -> status
    const seenFinding = new Map<string, string>();       // id -> status
    let first = true;

    const emit = (event: string, data: Record<string, unknown>): DarkmoonEvent | null => {
      if (wanted && !wanted.has(event)) return null;
      return { event, contractVersion: "1", seq: ++seq, deliveryId: null, ts: new Date().toISOString(), data };
    };

    for (;;) {
      if (opts.signal?.aborted) return;
      const campaigns = await this.listCampaigns().catch(() => []);
      for (const c of campaigns) {
        const prev = seenCampaign.get(c.id);
        const findings = await this.listFindings({ campaignId: c.id }, { includeEvidence: false }).catch(() => []);
        if (prev === undefined) {
          if (!first) {
            if (c.status === "running") { const e = emit("campaign.started", { campaign_id: c.id, target_id: c.targetId, status: c.status }); if (e) yield e; }
            if (["completed", "stopped", "failed"].includes(c.status)) { const e = emit(`campaign.${c.status === "failed" ? "aborted" : c.status}`, { campaign_id: c.id, target_id: c.targetId, status: c.status }); if (e) yield e; }
          }
        } else if (prev !== c.status && ["completed", "stopped", "failed"].includes(c.status)) {
          const e = emit(`campaign.${c.status === "failed" ? "aborted" : c.status}`, { campaign_id: c.id, target_id: c.targetId, status: c.status });
          if (e) yield e;
        }
        seenCampaign.set(c.id, c.status);
        for (const f of findings) {
          if (!f.id) continue;
          const prevF = seenFinding.get(f.id);
          if (prevF === undefined) {
            if (!first) {
              const e = emit("finding.discovered", safeFindingData(f, c.id)); if (e) yield e;
              if (["confirmed", "exploited", "remediated"].includes(f.status)) { const e2 = emit(`finding.${f.status}`, safeFindingData(f, c.id)); if (e2) yield e2; }
            }
          } else if (prevF !== f.status && ["confirmed", "exploited", "remediated"].includes(f.status)) {
            const e = emit(`finding.${f.status}`, safeFindingData(f, c.id)); if (e) yield e;
          }
          seenFinding.set(f.id, f.status);
        }
      }
      first = false;
      await sleep(pollMs);
    }
  }
}

function safeFindingData(f: Finding, campaignId: string): Record<string, unknown> {
  return {
    finding_id: f.id, campaign_id: campaignId, target_id: f.targetId, title: f.title,
    severity: f.severity, status: f.status, category: f.category, cve: f.cve,
    cvss_score: f.cvssScore, endpoint: f.endpoint, has_evidence: f.evidence != null,
  };
}

function randomHex(n: number): string {
  const bytes = new Uint8Array(Math.ceil(n / 2));
  webcrypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("").slice(0, n);
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

// Keep CorrelationFailed referenced for future strict-correlation mode.
void CorrelationFailed;
