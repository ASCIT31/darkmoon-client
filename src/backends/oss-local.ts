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
import { CampaignNotFound, CorrelationFailed, DarkmoonNotAvailable, FindingNotFound } from "../errors.js";

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
