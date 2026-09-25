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
import { httpRequest, safeUrl, type HttpResponse } from "../util/http.js";
import { readSse } from "../util/sse.js";
import { Logger } from "../util/logger.js";
import { normalizeCampaign, normalizeFinding, matchesFindingFilter } from "../normalize.js";
import { negotiateProVersion, parseCampaign, parseFindings } from "../schema.js";
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
import {
  AuthError,
  CampaignNotFound,
  CorrelationFailed,
  DarkmoonError,
  DarkmoonNotAvailable,
  FindingNotFound,
  InsecureDefaultError,
  NetworkError,
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
  /**
   * Opt-in bounded retry for idempotent GETs on transient NETWORK/5xx failures
   * (used by the v0.2.0 methods). Default 0 = no retry (preserves v0.1 behaviour).
   */
  retries?: number;
  /** Base backoff between retries in ms (exponential + jitter). Default 300. */
  backoffMs?: number;
  /** Opt-in client-side cap on list/timeseries result sizes. Default 0 = unlimited. */
  pageSize?: number;
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

  // ── v0.2.0 additive surface ────────────────────────────────────────────

  /** GET with opt-in bounded retry on transient NETWORK/5xx (idempotent only). */
  private async getWithRetry<T>(url: string, allowStatuses?: number[]): Promise<HttpResponse<T>> {
    const retries = Math.max(0, this.cfg.retries ?? 0);
    const base = this.cfg.backoffMs ?? 300;
    let lastErr: unknown;
    for (let attempt = 0; attempt <= retries; attempt++) {
      try {
        return await httpRequest<T>(url, { token: this.token, timeoutMs: this.cfg.timeoutMs, allowStatuses });
      } catch (err) {
        lastErr = err;
        const retryable = err instanceof NetworkError ||
          (err instanceof DarkmoonError && err.code === "NETWORK");
        if (!retryable || attempt === retries) break;
        const backoff = base * 2 ** attempt;
        await sleep(backoff + Math.random() * (backoff / 2));
      }
    }
    throw lastErr;
  }

  async registerWebhook(input: WebhookInput): Promise<WebhookRegistration> {
    await this.ensureAuth();
    const res = await httpRequest<{ data: any }>(`${this.apiBase}/webhooks`, {
      method: "POST",
      body: { url: input.url, events: input.events, secret: input.secret, format: input.format ?? "darkmoon" },
      token: this.token,
      timeoutMs: this.cfg.timeoutMs,
      allowStatuses: [400],
    });
    if (res.status === 400 || !res.data?.data) {
      throw new DarkmoonError("BAD_REQUEST", `Webhook registration rejected: ${extractDetail(res) ?? "invalid url/events"}.`);
    }
    return mapWebhook(res.data.data);
  }

  async listWebhooks(): Promise<WebhookRegistration[]> {
    await this.ensureAuth();
    const res = await this.getWithRetry<{ data: any[] }>(`${this.apiBase}/webhooks`);
    return (res.data?.data ?? []).map(mapWebhook);
  }

  async deleteWebhook(id: string): Promise<boolean> {
    await this.ensureAuth();
    const res = await httpRequest<any>(`${this.apiBase}/webhooks/${encodeURIComponent(id)}`, {
      method: "DELETE",
      token: this.token,
      timeoutMs: this.cfg.timeoutMs,
      allowStatuses: [404],
    });
    return res.status !== 404;
  }

  async launchRetest(input: RetestInput): Promise<RetestLaunchResult> {
    await this.ensureAuth();
    const res = await httpRequest<any>(`${this.apiBase}/retest`, {
      method: "POST",
      body: {
        target_id: input.targetId,
        campaign_id: input.campaignId,
        finding_ids: input.findingIds,
        safe_harbor: input.safeHarbor,
      },
      token: this.token,
      timeoutMs: this.cfg.timeoutMs,
      allowStatuses: [400, 403, 404],
    });
    if (res.status === 403) throw new DarkmoonError("BAD_REQUEST", "Retest target is out of scope (allowlist).");
    if (res.status === 404) throw new CampaignNotFound("Base campaign for retest not found.");
    if (res.status === 400 || !res.data?.retest_id) {
      throw new DarkmoonError("BAD_REQUEST", `Retest launch rejected: ${extractDetail(res) ?? "target_id or campaign_id required"}.`);
    }
    return {
      retestId: res.data.retest_id,
      runId: res.data.run_id ?? null,
      baseCampaignId: res.data.base_campaign_id ?? null,
      targetId: res.data.target_id ?? null,
    };
  }

  async getRetest(id: string): Promise<RetestResult> {
    const res = await this.getWithRetry<any>(`${this.apiBase}/retest/${encodeURIComponent(id)}`, [404]);
    if (res.status === 404 || !res.data?.retest_id) {
      throw new DarkmoonError("BAD_REQUEST", `Retest ${id} not found.`, { id });
    }
    return mapRetest(res.data, "pro");
  }

  async getEvidenceMeta(id: string): Promise<EvidenceMeta> {
    const res = await this.getWithRetry<any>(`${this.apiBase}/vulnerabilities/${encodeURIComponent(id)}/evidence-meta`, [404]);
    if (res.status === 404 || !res.data) {
      throw new FindingNotFound(`Finding ${id} not found.`, { id });
    }
    const d = res.data;
    return {
      vulnId: d.vuln_id ?? id,
      hasEvidence: Boolean(d.has_evidence),
      counts: {
        commands: Number(d.counts?.commands ?? 0),
        payloads: Number(d.counts?.payloads ?? 0),
        screenshots: Number(d.counts?.screenshots ?? 0),
        logs: Number(d.counts?.logs ?? 0),
        requests: Number(d.counts?.requests ?? 0),
      },
      commandNames: Array.isArray(d.command_names) ? d.command_names.map(String) : [],
      hasScreenshot: Boolean(d.has_screenshot),
      hasExtractedData: Boolean(d.has_extracted_data),
      redacted: d.redacted !== false,
    };
  }

  async getTimeseries(query: TimeseriesQuery = {}): Promise<TimeseriesResult> {
    const qs = new URLSearchParams();
    qs.set("metric", query.metric ?? "severity");
    qs.set("group", query.group ?? "day");
    if (query.projectId) qs.set("project_id", query.projectId);
    if (query.targetId) qs.set("target_id", query.targetId);
    if (query.from) qs.set("from", query.from);
    if (query.to) qs.set("to", query.to);
    const res = await this.getWithRetry<any>(`${this.apiBase}/metrics/timeseries?${qs}`, [400]);
    if (res.status === 400) throw new DarkmoonError("BAD_REQUEST", `Invalid timeseries query: ${extractDetail(res) ?? "bad metric/group"}.`);
    let series = Array.isArray(res.data?.series) ? res.data.series : [];
    const cap = this.cfg.pageSize ?? 0;
    if (cap > 0) series = series.slice(0, cap);
    return {
      metric: String(res.data?.metric ?? query.metric ?? "severity"),
      group: String(res.data?.group ?? query.group ?? "day"),
      series: series.map((s: any) => ({
        key: String(s.key),
        points: (s.points ?? []).map((p: any) => ({ t: String(p.t), value: Number(p.value ?? 0) })),
      })),
      edition: "pro",
    };
  }

  /**
   * Consolidated event stream via the Pro SSE feed (/events/stream), replayable
   * from the `since` cursor. Yields normalized DarkmoonEvents until the caller
   * breaks, the connection ends, or the AbortSignal fires.
   */
  async *streamEvents(opts: EventStreamOptions = {}): AsyncIterable<DarkmoonEvent> {
    await this.ensureAuth();
    const qs = new URLSearchParams();
    qs.set("since", String(opts.since ?? 0));
    if (opts.events?.length) qs.set("events", opts.events.join(","));
    const url = `${this.apiBase}/events/stream?${qs}`;
    for await (const raw of readSse(url, { token: this.token, signal: opts.signal })) {
      const e = raw as any;
      if (!e || typeof e !== "object" || !e.event) continue;
      yield mapEvent(e);
    }
  }
}

function extractDetail(res: HttpResponse<any>): string | null {
  const d = (res.data as any)?.detail;
  return typeof d === "string" ? d : null;
}

function mapWebhook(row: any): WebhookRegistration {
  return {
    id: String(row.id),
    url: String(row.url ?? ""),
    events: Array.isArray(row.events) ? row.events.map(String) : [],
    format: String(row.format ?? "darkmoon"),
    enabled: row.enabled !== false,
    createdAt: row.created_at ?? null,
    ...(typeof row.secret === "string" ? { secret: row.secret } : {}),
  };
}

function mapRetest(d: any, edition: "oss" | "pro"): RetestResult {
  const summary = d.verdicts_summary ?? {};
  return {
    retestId: String(d.retest_id),
    baseCampaignId: d.base_campaign_id ?? null,
    newCampaignId: d.new_campaign_id ?? null,
    targetId: d.target_id ?? null,
    runId: d.run_id ?? null,
    status: d.status === "completed" ? "completed" : "running",
    verdictsSummary: {
      fixed: Number(summary.fixed ?? 0),
      still_present: Number(summary.still_present ?? 0),
      regressed: Number(summary.regressed ?? 0),
      new: Number(summary.new ?? 0),
    },
    findings: (d.findings ?? []).map((f: any) => ({
      findingId: f.finding_id ?? null,
      newFindingId: f.new_finding_id ?? null,
      baseStatus: f.base_status ?? null,
      newStatus: f.new_status ?? null,
      severity: f.severity ?? null,
      verdict: f.verdict,
    })),
    edition,
  };
}

function mapEvent(e: any): DarkmoonEvent {
  return {
    event: String(e.event),
    contractVersion: String(e.contract_version ?? "1"),
    seq: Number(e.seq ?? 0),
    deliveryId: e.delivery_id ?? null,
    ts: e.ts ?? null,
    data: (e.data && typeof e.data === "object") ? e.data : {},
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
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
