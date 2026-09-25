/**
 * @darkmoon_ai/client — FROZEN public contract (§2.2 of the integrations plan).
 *
 * These types are the single source of truth that the 5 official integrations
 * (GitHub Actions, GitLab CI/CD, Jenkins, VS Code, JetBrains) build against.
 * A Kotlin port (JetBrains) mirrors these shapes and reuses the same
 * conformance fixtures. DO NOT change method signatures or the canonical enum
 * value sets without bumping CONTRACT_VERSION (semver) and the fixtures.
 */

/** Contract version. Integrations pin against the major. */
export const CONTRACT_VERSION = "1.0.0" as const;

/** Canonical, lowercase severity set. Everything normalizes into this. */
export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof SEVERITIES)[number];

/** Canonical finding status set. */
export const FINDING_STATUSES = [
  "exploited",
  "confirmed",
  "unconfirmed",
  "remediated",
] as const;
export type FindingStatus = (typeof FINDING_STATUSES)[number];

/** Canonical campaign lifecycle status. */
export const CAMPAIGN_STATUSES = [
  "queued",
  "running",
  "completed",
  "stopped",
  "failed",
  "unknown",
] as const;
export type CampaignStatus = (typeof CAMPAIGN_STATUSES)[number];

/** Which Darkmoon backend served a call. */
export type Edition = "oss" | "pro";

/** Backend selection override. */
export type ClientMode = "auto" | "oss" | "pro";

/**
 * Capabilities returned by detect(). `features` is a normalized, additive map so
 * integrations can gate UI/behaviour without sniffing the edition directly.
 */
export interface Capabilities {
  edition: Edition;
  /** Effective mode after auto-detection resolved. */
  mode: Exclude<ClientMode, "auto">;
  /** Backend version string (Pro: API version; OSS: CLI/image version or "unknown"). */
  version: string;
  /** True when the client could positively confirm the backend is reachable. */
  available: boolean;
  features: {
    /** REST API surface (Pro only). */
    restApi: boolean;
    /** Server-Sent Events progress streaming (Pro only). */
    streaming: boolean;
    /** JWT auth is enforced/available. */
    auth: boolean;
    /** Remediation → pull-request phase (Pro only). */
    remediation: boolean;
    /** Web dashboard GUI (Pro only). */
    dashboard: boolean;
    /** Scheduled campaigns (Pro only). */
    scheduler: boolean;
  };
  /** How detection concluded, for diagnostics (never contains secrets). */
  detectedBy: "system-info" | "root-probe" | "cli-probe" | "override" | "config";
  /**
   * Backend-reported warnings that the caller MUST surface — e.g. the Pro admin
   * still has the default password / must_change_password. Never contains a secret.
   */
  warnings: string[];
}

/** Aggregated severity counts for a campaign (the redaction-safe default surface). */
export interface SeveritySummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

/** A normalized campaign. Backend-specific extras live under `raw` (never logged). */
export interface Campaign {
  id: string;
  projectId: string | null;
  targetId: string | null;
  /** Short session correlation id (OSS: opencode session fragment). */
  sessionId: string | null;
  /** Primary target host/URL if resolvable from stored data. */
  target: string | null;
  status: CampaignStatus;
  /** Highest overall risk, normalized to a severity or "none". */
  overallRisk: Severity | "none";
  createdAt: string | null;
  durationSeconds: number | null;
  reportPath: string | null;
  isSubagent: boolean;
  severity: SeveritySummary;
  /** Executive summary text if present (report prose, not evidence). */
  executiveSummary: string | null;
  edition: Edition;
  /** Raw stored object. Internal only — MUST NOT be logged or serialized to CI output. */
  raw?: unknown;
}

/** Evidence attached to a finding. Redacted unless explicitly opted-in. */
export interface FindingEvidence {
  commands: string[];
  payloads: string[];
  rawRequest: string | null;
  rawResponse: string | null;
  extractedData: string | null;
  logs: string[];
  explanation: string | null;
  /** True when this evidence object has been passed through the redactor. */
  redacted: boolean;
}

/** A normalized finding / vulnerability. */
export interface Finding {
  id: string;
  campaignId: string | null;
  projectId: string | null;
  targetId: string | null;
  title: string | null;
  severity: Severity;
  status: FindingStatus;
  category: string | null;
  cve: string | null;
  cvssScore: number | null;
  cvssVector: string | null;
  mitreAttackId: string | null;
  mitreAttackName: string | null;
  endpoint: string | null;
  description: string | null;
  remediation: string | null;
  discoveredByAgent: string | null;
  discoveredAt: string | null;
  /** Redaction-safe by default; only carries evidence when includeEvidence is set. */
  evidence: FindingEvidence | null;
  edition: Edition;
  raw?: unknown;
}

/** A campaign report. `ready` distinguishes a real report from a Pro placeholder-200. */
export interface Report {
  campaignId: string;
  format: string;
  /** Report body. Redacted by default; full body only with an explicit opt-in. */
  content: string;
  ready: boolean;
  redacted: boolean;
}

/** Live progress event surfaced by streamProgress(). */
export interface ProgressEvent {
  type: string;
  /** Best-effort correlation to a campaign once known. */
  campaignId?: string | null;
  runId?: string | null;
  /** Human-readable, secret-free message. */
  message?: string;
  /** Terminal marker (run_completed / run_error / correlation resolved). */
  terminal?: boolean;
  raw?: unknown;
}

/** Input to launchCampaign(). Mirrors the Pro CampaignRunRequest + OSS prompt flags. */
export interface LaunchInput {
  target: string;
  program?: string;
  targets?: string[];
  outOfScope?: string[];
  exclude?: string[];
  focus?: string[];
  credentials?: string[];
  tokens?: string[];
  noise?: string;
  severity?: string;
  format?: string;
  rules?: string[];
  safeHarbor?: string;
  /** Pro remediation phase (opt-in). credentialId is an opaque ref, never a secret. */
  remediate?: boolean;
  gitRepo?: string;
  credentialId?: string;
  createRepo?: boolean;
}

/**
 * Opaque correlation handle returned by launchCampaign(). Callers pass it back to
 * getCampaignStatus/waitForCompletion/streamProgress. Shape is backend-specific
 * and internal; treat it as a token.
 */
export interface CorrelationHandle {
  edition: Edition;
  /** Pro run id (null for OSS). */
  runId: string | null;
  /** Resolved campaign id once correlation succeeds (may start null). */
  campaignId: string | null;
  /** OSS: unique PROGRAM nonce injected into the run. */
  nonce: string | null;
  /** OSS: campaign ids present before launch (snapshot for diff correlation). */
  preCampaignIds?: string[];
  /** Epoch ms at launch, for mtime-based tie-breaking. */
  startedAtMs: number;
}

/** Result of launchCampaign(). */
export interface LaunchResult {
  correlation: CorrelationHandle;
  /** True if a campaign id was already known at launch (rare; usually resolved later). */
  campaignId: string | null;
  runId: string | null;
}

/** A campaign reference: an id string, a CorrelationHandle, or a LaunchResult. */
export type CampaignRef = string | CorrelationHandle | LaunchResult;

/** Options for waitForCompletion(). */
export interface WaitOptions {
  /** Hard timeout in ms. A run still not terminal after this is treated as FAILURE. */
  timeoutMs?: number;
  /** Poll interval in ms (OSS + Pro polling fallback). */
  pollIntervalMs?: number;
  /** Called on each observed status transition (secret-free). */
  onProgress?: (c: Campaign) => void;
  /** Treat a campaign stuck in `unknown`/`running` past timeout as failed (default true). */
  failOnStuck?: boolean;
}

/** Filters for listCampaigns / listFindings. */
export interface CampaignFilter {
  targetId?: string;
  status?: string;
}

export interface FindingFilter {
  campaignId?: string;
  projectId?: string;
  targetId?: string;
  severity?: string;
  category?: string;
  status?: string;
}

/** Options for getReport(). Full body is internal-only and opt-in. */
export interface ReportOptions {
  /**
   * Opt in to the full, UN-redacted report body. This body contains rehydrated
   * real values (hosts, extracted data, evidence). Internal use only — never emit
   * to CI logs or artifacts without an explicit operator decision.
   */
  full?: boolean;
  /** Required companion flag to `full` — a deliberate two-key opt-in. */
  private?: boolean;
}

/** Options for getFinding / listFindings evidence exposure. */
export interface FindingReadOptions {
  /** Include (redacted) evidence objects. Default false → evidence is null. */
  includeEvidence?: boolean;
  /** With includeEvidence, opt in to UN-redacted evidence (internal only). */
  full?: boolean;
  private?: boolean;
}

/** The frozen client surface. Both backends and the facade implement it. */
export interface DarkmoonClientContract {
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
}
