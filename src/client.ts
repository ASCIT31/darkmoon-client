import type {
  Campaign,
  CampaignFilter,
  CampaignRef,
  Capabilities,
  ClientMode,
  CorrelationHandle,
  DarkmoonClientContract,
  Finding,
  FindingFilter,
  FindingReadOptions,
  LaunchInput,
  LaunchResult,
  ProgressEvent,
  Report,
  ReportOptions,
  SeveritySummary,
  WaitOptions,
} from "./contract.js";
import type { Backend } from "./backends/backend.js";
import { ProHttpBackend, type ProHttpConfig } from "./backends/pro-http.js";
import { OssLocalBackend, type OssLocalConfig } from "./backends/oss-local.js";
import { Logger, type LogLevel } from "./util/logger.js";
import { redactReport } from "./redact.js";
import {
  DarkmoonError,
  DarkmoonNotAvailable,
  ReportNotReady,
  StuckCampaignError,
  NotSupported,
} from "./errors.js";

export interface DarkmoonClientConfig {
  /** Backend selection. Default "auto" (prefer Pro if reachable, else OSS). */
  mode?: ClientMode;
  pro?: ProHttpConfig;
  oss?: OssLocalConfig;
  logLevel?: LogLevel;
  logger?: Logger;
}

const TERMINAL = new Set(["completed", "stopped", "failed"]);
const STUCK = new Set(["running", "queued", "unknown"]);

/**
 * The one public entry point. Wraps one backend (Pro or OSS) behind the frozen
 * contract and owns the cross-cutting policy: redaction defaults, hard-timeout /
 * stuck-campaign handling, and never deriving pass/fail from a process exit code.
 */
export class DarkmoonClient implements DarkmoonClientContract {
  private cfg: DarkmoonClientConfig;
  private log: Logger;
  private backend: Backend | null = null;
  private caps: Capabilities | null = null;

  constructor(cfg: DarkmoonClientConfig = {}) {
    this.cfg = cfg;
    this.log = cfg.logger ?? new Logger(cfg.logLevel ?? "warn");
  }

  /** Detect the active backend (cached). Applies the mode override. */
  async detect(): Promise<Capabilities> {
    if (this.caps) return this.caps;
    const mode = this.cfg.mode ?? "auto";

    if (mode === "pro") {
      this.backend = this.makePro();
      this.caps = await this.backend.detect();
      return this.caps;
    }
    if (mode === "oss") {
      this.backend = this.makeOss();
      this.caps = await this.backend.detect();
      return this.caps;
    }

    // auto: prefer Pro if configured & reachable, then OSS.
    const errors: string[] = [];
    if (this.cfg.pro) {
      try {
        const pro = this.makePro();
        const caps = await pro.detect();
        this.backend = pro;
        this.caps = caps;
        return caps;
      } catch (err) {
        errors.push(`pro: ${(err as Error).message}`);
      }
    }
    if (this.cfg.oss) {
      try {
        const oss = this.makeOss();
        const caps = await oss.detect();
        this.backend = oss;
        this.caps = caps;
        return caps;
      } catch (err) {
        errors.push(`oss: ${(err as Error).message}`);
      }
    }
    throw new DarkmoonNotAvailable(
      `No Darkmoon backend reachable in auto mode. ${errors.join("; ") || "No pro/oss config provided."}`,
    );
  }

  private makePro(): ProHttpBackend {
    if (!this.cfg.pro) throw new DarkmoonNotAvailable("Pro mode selected but no `pro` config was provided.");
    return new ProHttpBackend({ ...this.cfg.pro, logger: this.log });
  }
  private makeOss(): OssLocalBackend {
    if (!this.cfg.oss) throw new DarkmoonNotAvailable("OSS mode selected but no `oss` config was provided.");
    return new OssLocalBackend({ ...this.cfg.oss, logger: this.log });
  }

  private async be(): Promise<Backend> {
    if (!this.backend) await this.detect();
    return this.backend!;
  }

  /** The resolved edition (after detect). */
  get edition(): Capabilities["edition"] | null {
    return this.caps?.edition ?? null;
  }

  async launchCampaign(input: LaunchInput): Promise<LaunchResult> {
    if (!input?.target) throw new DarkmoonError("BAD_REQUEST", "launchCampaign requires a `target`.");
    return (await this.be()).launchCampaign(input);
  }

  private static toHandle(ref: CampaignRef): CorrelationHandle | string {
    if (typeof ref === "string") return ref;
    if ("correlation" in ref) return ref.correlation;
    return ref;
  }

  async getCampaignStatus(ref: CampaignRef): Promise<Campaign> {
    return (await this.be()).getCampaignStatus(DarkmoonClient.toHandle(ref));
  }

  async listCampaigns(filter?: CampaignFilter): Promise<Campaign[]> {
    return (await this.be()).listCampaigns(filter);
  }

  async getCampaign(id: CampaignRef): Promise<Campaign> {
    const be = await this.be();
    const handle = DarkmoonClient.toHandle(id);
    const cid = typeof handle === "string" ? handle : await be.resolveCampaignId(handle);
    if (!cid) throw new DarkmoonError("CAMPAIGN_NOT_FOUND", "Campaign reference could not be resolved to an id.");
    return be.getCampaign(cid);
  }

  async listFindings(filter: FindingFilter, opts?: FindingReadOptions): Promise<Finding[]> {
    DarkmoonClient.assertFullOptIn(opts);
    return (await this.be()).listFindings(filter, opts);
  }

  async getFinding(id: string, opts?: FindingReadOptions): Promise<Finding> {
    DarkmoonClient.assertFullOptIn(opts);
    return (await this.be()).getFinding(id, opts);
  }

  async getSeveritySummary(campaign: CampaignRef): Promise<SeveritySummary> {
    const c = await this.getCampaign(campaign);
    return c.severity;
  }

  async getReport(campaign: CampaignRef, opts?: ReportOptions): Promise<Report> {
    const be = await this.be();
    const handle = DarkmoonClient.toHandle(campaign);
    const cid = typeof handle === "string" ? handle : await be.resolveCampaignId(handle);
    if (!cid) throw new DarkmoonError("CAMPAIGN_NOT_FOUND", "Campaign reference could not be resolved to an id.");
    const raw = await be.getReport(cid);
    if (!raw.ready) {
      throw new ReportNotReady(`Report for ${cid} is not ready yet (placeholder or empty).`, { campaignId: cid });
    }
    const wantFull = Boolean(opts?.full);
    if (wantFull && !opts?.private) {
      throw new DarkmoonError(
        "BAD_REQUEST",
        "getReport({ full: true }) also requires `private: true` — the full report contains rehydrated real values and must not be emitted to CI logs/artifacts by accident.",
      );
    }
    const content = wantFull ? raw.content : redactReport(raw.content);
    return { campaignId: cid, format: raw.format, content, ready: true, redacted: !wantFull };
  }

  /**
   * Poll until the campaign reaches a terminal state. Enforces a HARD timeout:
   * a campaign still running/unknown past `timeoutMs` is treated as a FAILURE
   * (StuckCampaignError), never a pass. We NEVER derive pass/fail from an exit
   * code — status and findings are the source of truth.
   */
  async waitForCompletion(ref: CampaignRef, opts: WaitOptions = {}): Promise<Campaign> {
    const timeoutMs = opts.timeoutMs ?? 60 * 60 * 1000; // 1h default
    const pollIntervalMs = opts.pollIntervalMs ?? 5000;
    const failOnStuck = opts.failOnStuck ?? true;
    const deadline = Date.now() + timeoutMs;
    const be = await this.be();
    const handle = DarkmoonClient.toHandle(ref);

    let last: Campaign | null = null;
    for (;;) {
      const c = await be.getCampaignStatus(handle);
      if (!last || last.status !== c.status) {
        opts.onProgress?.(c);
        last = c;
      }
      if (TERMINAL.has(c.status)) return c;
      if (Date.now() >= deadline) {
        if (failOnStuck && STUCK.has(c.status)) {
          throw new StuckCampaignError(
            `Campaign ${c.id} still '${c.status}' after ${Math.round(timeoutMs / 1000)}s — treating as failure.`,
            { campaignId: c.id, status: c.status },
          );
        }
        return c;
      }
      await sleep(Math.min(pollIntervalMs, Math.max(0, deadline - Date.now())));
    }
  }

  async *streamProgress(ref: CampaignRef): AsyncIterable<ProgressEvent> {
    const be = await this.be();
    yield* be.streamProgress(DarkmoonClient.toHandle(ref));
  }

  private static assertFullOptIn(opts?: FindingReadOptions): void {
    if (opts?.full && !opts?.private) {
      throw new DarkmoonError(
        "BAD_REQUEST",
        "Evidence `full: true` also requires `private: true` (internal-only opt-in for rehydrated real values).",
      );
    }
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

// referenced to satisfy noUnusedLocals for the re-export surface
void NotSupported;
