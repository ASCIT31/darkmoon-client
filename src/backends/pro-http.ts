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
import { webcrypto } from "node:crypto";
import type { Backend, RawReport } from "./backend.js";
import { refToId } from "./backend.js";
import { httpRequest, safeUrl } from "../util/http.js";
import { readSse } from "../util/sse.js";
import { Logger } from "../util/logger.js";
import { normalizeCampaign, normalizeFinding, matchesFindingFilter } from "../normalize.js";
import { negotiateProVersion, parseCampaign, parseFindings } from "../schema.js";
import {
  AuthError,
  CampaignNotFound,
  CorrelationFailed,
  DarkmoonNotAvailable,
  FindingNotFound,
  InsecureDefaultError,
} from "../errors.js";

const REPORT_PLACEHOLDER_PREFIX = "# Report not found";

export interface ProHttpConfig {
  /** Base URL, with or without the /api/v1 suffix. */
  baseUrl: string;
  username?: string;
  password?: string;
  /** Pre-obtained bearer token (skips login). */
  token?: string;
  timeoutMs?: number;
  logger?: Logger;
  /**
   * If true (default), refuse to operate when the Pro backend reports the admin
   * still has must_change_password / a default secret. Set false to only warn.
   */
  refuseInsecureDefault?: boolean;
}

export class ProHttpBackend implements Backend {
  readonly edition = "pro" as const;
  private base: string;
  private apiBase: string;
  private token: string | null;
  private log: Logger;
  private cfg: ProHttpConfig;
  private mustChangePassword = false;

  constructor(cfg: ProHttpConfig) {
    this.cfg = cfg;
    this.base = cfg.baseUrl.replace(/\/+$/, "").replace(/\/api\/v1$/, "");
    this.apiBase = `${this.base}/api/v1`;
    this.token = cfg.token ?? null;
    this.log = cfg.logger ?? new Logger("warn");
  }

  private async ensureAuth(): Promise<void> {
    if (this.token) return;
    if (!this.cfg.username || !this.cfg.password) return; // unauthenticated GET path (API allows it)
    const res = await httpRequest<{ token: string; must_change_password?: boolean; user?: any }>(
      `${this.apiBase}/auth/login`,
      {
        method: "POST",
        body: { username: this.cfg.username, password: this.cfg.password },
        timeoutMs: this.cfg.timeoutMs,
        allowStatuses: [401],
      },
    );
    if (res.status === 401 || !res.data?.token) {
      throw new AuthError("Login rejected by the Pro API.", { url: safeUrl(`${this.apiBase}/auth/login`) });
    }
    this.token = res.data.token;
    this.mustChangePassword = Boolean(res.data.must_change_password ?? res.data.user?.must_change_password);
    if (this.mustChangePassword) {
      const msg = "Pro admin account still has its default password (must_change_password=true). Rotate it before using CI.";
      if (this.cfg.refuseInsecureDefault !== false) {
        throw new InsecureDefaultError(msg);
      }
      this.log.warn(msg);
    }
  }

  async detect(): Promise<Capabilities> {
    const warnings: string[] = [];
    // Default Pro feature set (used when only the root probe is available).
    let features: Capabilities["features"] = {
      restApi: true,
      streaming: true,
      auth: true,
      remediation: true,
      dashboard: true,
      scheduler: true,
    };
    let version = "unknown";
    let detectedBy: Capabilities["detectedBy"] = "root-probe";

    // Prefer GET /system/info (a parallel Pro task adds it). Shape:
    // { edition, api_version, contract_version, features: { auth, credentials,
    //   scheduler, sse_progress, remediation, privacy_gateway, licensing }, ... }
    try {
      const info = await httpRequest<any>(`${this.apiBase}/system/info`, { timeoutMs: this.cfg.timeoutMs, allowStatuses: [404] });
      const d = info.data;
      if (info.status !== 404 && d && (d.edition || d.api_version || d.version)) {
        version = String(d.api_version ?? d.version ?? "unknown");
        detectedBy = "system-info";
        if (d.features && typeof d.features === "object") {
          features = {
            restApi: true,
            streaming: Boolean(d.features.sse_progress ?? true),
            auth: Boolean(d.features.auth ?? true),
            remediation: Boolean(d.features.remediation ?? true),
            dashboard: true,
            scheduler: Boolean(d.features.scheduler ?? true),
          };
        }
        if (d.edition && String(d.edition).toLowerCase() !== "pro") {
          warnings.push(`system/info reports edition="${d.edition}", expected "pro".`);
        }
      } else {
        throw new Error("no system/info");
      }
    } catch {
      // Fall back to the heuristic root probe (GET / → service + version).
      try {
        const root = await httpRequest<any>(`${this.base}/`, { timeoutMs: this.cfg.timeoutMs });
        const svc = String(root.data?.service ?? "");
        if (!/darkmoon/i.test(svc)) {
          warnings.push(`Root service string "${svc}" does not look like a Darkmoon API.`);
        }
        version = String(root.data?.version ?? "unknown");
        detectedBy = "root-probe";
      } catch {
        throw new DarkmoonNotAvailable("Pro API root probe failed.", { url: safeUrl(this.base) });
      }
    }
    const negotiated = negotiateProVersion(version);
    if (this.mustChangePassword) {
      warnings.push("Pro admin still has must_change_password=true.");
    }
    return {
      edition: "pro",
      mode: "pro",
      version: negotiated.version,
      available: true,
      features,
      detectedBy,
      warnings,
    };
  }

  async launchCampaign(input: LaunchInput): Promise<LaunchResult> {
    await this.ensureAuth();
    // Snapshot campaign ids for correlation fallback.
    let preCampaignIds: string[] = [];
    try {
      const before = await this.listCampaigns();
      preCampaignIds = before.map((c) => c.id);
    } catch {
      /* best effort */
    }
    const nonce = input.program ?? `ci-${randomHex(8)}`;
    const body = {
      target: input.target,
      program: nonce,
      targets: input.targets,
      out_of_scope: input.outOfScope,
      exclude: input.exclude,
      focus: input.focus,
      credentials: input.credentials,
      tokens: input.tokens,
      noise: input.noise,
      severity: input.severity,
      format: input.format,
      rules: input.rules,
      safe_harbor: input.safeHarbor,
      remediate: input.remediate,
      git_repo: input.gitRepo,
      credential_id: input.credentialId,
      create_repo: input.createRepo,
    };
    const res = await httpRequest<{ run_id: string; pid?: number | null }>(`${this.apiBase}/run/campaign`, {
      method: "POST",
      body,
      token: this.token,
      timeoutMs: this.cfg.timeoutMs,
    });
    const runId = res.data?.run_id ?? null;
    const correlation: CorrelationHandle = {
      edition: "pro",
      runId,
      campaignId: null,
      nonce,
      preCampaignIds,
      startedAtMs: Date.now(),
    };
    return { correlation, campaignId: null, runId };
  }

  /**
   * Correlate a Pro run_id to its campaign_id. The run stream/logs carry the
   * opencode session id (ses_XXXX...); the campaign's session_id is a fragment
   * of it. Fallback: the single campaign that appeared since launch.
   */
  async resolveCampaignId(ref: CorrelationHandle | string): Promise<string | null> {
    const direct = refToId(ref);
    if (direct) return direct;
    if (typeof ref === "string") return ref;
    if (ref.campaignId) return ref.campaignId;

    // 1) session-id correlation from the run log
    if (ref.runId) {
      try {
        const logs = await httpRequest<{ data: any[] }>(`${this.apiBase}/run/logs/${encodeURIComponent(ref.runId)}`, {
          token: this.token,
          timeoutMs: this.cfg.timeoutMs,
          allowStatuses: [404],
        });
        const sid = extractSessionId(logs.data?.data ?? []);
        if (sid) {
          const frag = sid.replace(/^ses_/, "").slice(0, 8);
          const all = await this.listCampaigns();
          const hit = all.find((c) => (c.sessionId ?? "").includes(frag) || c.id.includes(frag));
          if (hit) {
            ref.campaignId = hit.id;
            return hit.id;
          }
        }
      } catch {
        /* fall through */
      }
    }
    // 2) new-campaign-since-launch diff
    try {
      const now = await this.listCampaigns();
      const pre = new Set(ref.preCampaignIds ?? []);
      const fresh = now.filter((c) => !pre.has(c.id));
      if (fresh.length === 1) {
        ref.campaignId = fresh[0]!.id;
        return fresh[0]!.id;
      }
      if (fresh.length > 1) {
        // Multiple concurrent runs — cannot safely attribute.
        throw new CorrelationFailed("Multiple new campaigns since launch; ambiguous correlation.", { candidates: fresh.map((c) => c.id) });
      }
    } catch (err) {
      if (err instanceof CorrelationFailed) throw err;
    }
    return null;
  }

  async getCampaignStatus(ref: CorrelationHandle | string): Promise<Campaign> {
    const id = await this.resolveCampaignId(ref);
    if (!id) {
      // Not yet correlated: report a synthetic running campaign.
      const runId = typeof ref === "string" ? null : ref.runId;
      return syntheticRunning(runId);
    }
    return this.getCampaign(id);
  }

  async listCampaigns(filter?: CampaignFilter): Promise<Campaign[]> {
    const qs = new URLSearchParams();
    if (filter?.targetId) qs.set("target_id", filter.targetId);
    if (filter?.status) qs.set("status", filter.status);
    const url = `${this.apiBase}/campaigns${qs.toString() ? `?${qs}` : ""}`;
    const res = await httpRequest<{ data: any[] }>(url, { token: this.token, timeoutMs: this.cfg.timeoutMs });
    const items = res.data?.data ?? [];
    return items.map((c) => normalizeCampaign(parseCampaign(c), "pro"));
  }

  async getCampaign(id: string): Promise<Campaign> {
    const res = await httpRequest<{ data: any }>(`${this.apiBase}/campaigns/${encodeURIComponent(id)}`, {
      token: this.token,
      timeoutMs: this.cfg.timeoutMs,
      allowStatuses: [404],
    });
    if (res.status === 404 || !res.data?.data) {
      throw new CampaignNotFound(`Campaign ${id} not found.`, { id });
    }
    const raw = res.data.data;
    const campaign = normalizeCampaign(parseCampaign(raw), "pro");
    // Detail includes vulnerabilities → recompute authoritative severity summary.
    if (Array.isArray(raw.vulnerabilities)) {
      const findings = raw.vulnerabilities.map((v: any) => normalizeFinding(v, "pro"));
      campaign.severity = {
        critical: findings.filter((f: Finding) => f.severity === "critical").length,
        high: findings.filter((f: Finding) => f.severity === "high").length,
        medium: findings.filter((f: Finding) => f.severity === "medium").length,
        low: findings.filter((f: Finding) => f.severity === "low").length,
        info: findings.filter((f: Finding) => f.severity === "info").length,
        total: findings.length,
      };
    }
    return campaign;
  }

  async listFindings(filter: FindingFilter, opts?: FindingReadOptions): Promise<Finding[]> {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries({
      campaign_id: filter.campaignId,
      project_id: filter.projectId,
      target_id: filter.targetId,
      severity: filter.severity,
      category: filter.category,
      status: filter.status,
    })) {
      if (v) qs.set(k, String(v));
    }
    const url = `${this.apiBase}/vulnerabilities${qs.toString() ? `?${qs}` : ""}`;
    const res = await httpRequest<{ data: any[] }>(url, { token: this.token, timeoutMs: this.cfg.timeoutMs });
    const raws = parseFindings(res.data);
    let findings = raws.map((v) => normalizeFinding(v as any, "pro", { includeEvidence: opts?.includeEvidence, full: opts?.full }));
    // Safety net: apply filter client-side too (list endpoint returns evidence-less items).
    findings = findings.filter((f) => matchesFindingFilter(f, filter));
    // The list endpoint does not include evidence; fetch detail if evidence asked.
    if (opts?.includeEvidence) {
      findings = await Promise.all(findings.map((f) => (f.id ? this.getFinding(f.id, opts) : Promise.resolve(f))));
    }
    return findings;
  }

  async getFinding(id: string, opts?: FindingReadOptions): Promise<Finding> {
    const res = await httpRequest<{ data: any }>(`${this.apiBase}/vulnerabilities/${encodeURIComponent(id)}`, {
      token: this.token,
      timeoutMs: this.cfg.timeoutMs,
      allowStatuses: [404],
    });
    if (res.status === 404 || !res.data?.data) {
      throw new FindingNotFound(`Finding ${id} not found.`, { id });
    }
    return normalizeFinding(res.data.data, "pro", { includeEvidence: opts?.includeEvidence, full: opts?.full });
  }

  async getReport(campaignId: string): Promise<RawReport> {
    const res = await httpRequest<{ campaign_id?: string; format?: string; content?: string }>(
      `${this.apiBase}/campaigns/${encodeURIComponent(campaignId)}/report`,
      { token: this.token, timeoutMs: this.cfg.timeoutMs, allowStatuses: [404] },
    );
    if (res.status === 404) {
      throw new CampaignNotFound(`Campaign ${campaignId} not found.`, { id: campaignId });
    }
    const content = res.data?.content ?? "";
    const ready = content.length > 0 && !content.startsWith(REPORT_PLACEHOLDER_PREFIX);
    return { campaignId, format: res.data?.format ?? "markdown", content, ready };
  }

  async *streamProgress(ref: CorrelationHandle | string): AsyncIterable<ProgressEvent> {
    const runId = typeof ref === "string" ? null : ref.runId;
    if (!runId) {
      throw new CorrelationFailed("streamProgress requires a Pro run id (launch the campaign via launchCampaign).");
    }
    for await (const evt of readSse(`${this.apiBase}/run/${encodeURIComponent(runId)}/stream`, { token: this.token })) {
      const e = evt as any;
      const type = String(e?.type ?? "event");
      const terminal = type === "run_completed" || type === "run_error";
      yield {
        type,
        runId,
        campaignId: typeof ref === "string" ? null : ref.campaignId,
        message: typeof e?.text === "string" ? e.text : undefined,
        terminal,
        raw: e,
      };
      if (terminal) return;
    }
  }
}

function syntheticRunning(runId: string | null): Campaign {
  return {
    id: runId ? `run:${runId}` : "run:pending",
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
    edition: "pro",
  };
}

function extractSessionId(events: any[]): string | null {
  for (const e of events) {
    const sid = e?.sessionID ?? e?.session_id ?? e?.part?.sessionID;
    if (typeof sid === "string" && sid.startsWith("ses_")) return sid;
  }
  return null;
}

function randomHex(n: number): string {
  const bytes = new Uint8Array(Math.ceil(n / 2));
  webcrypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("").slice(0, n);
}
