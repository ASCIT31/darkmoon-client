/**
 * @darkmoon_ai/client — v0.2.0 ADDITIVE surface (Phase-2 integrations).
 *
 * These types + the matching client methods (registerWebhook / listWebhooks /
 * deleteWebhook, launchRetest / getRetest, getEvidenceMeta, getTimeseries,
 * streamEvents) are ADDITIVE on top of the FROZEN v1 contract. They do NOT change
 * any v1 signature or enum set, so CONTRACT_VERSION stays "1.0.0". The three new
 * integrations (Splunk / Grafana / n8n) build against these.
 */
import type { Edition, Severity } from "./contract.js";

// ── Webhooks (Pro-only; OSS has no server → NotSupported) ────────────────

export interface WebhookInput {
  /** HTTPS endpoint the Pro dispatcher POSTs signed events to. */
  url: string;
  /** Event types to receive; empty/omitted = all. */
  events?: string[];
  /** HMAC secret; the server generates + returns one once if omitted. */
  secret?: string;
  /** Payload format (only "darkmoon" is shipped). */
  format?: string;
}

export interface WebhookRegistration {
  id: string;
  url: string;
  events: string[];
  format: string;
  enabled: boolean;
  createdAt: string | null;
  /**
   * The HMAC secret. Present (unmasked) ONLY on the create response — store it
   * then; subsequent reads return it masked ("set:xxxx"). Used to verify the
   * `X-Darkmoon-Signature: sha256=<hmac(secret, rawBody)>` on each delivery.
   */
  secret?: string;
}

// ── Retest + derived verdict ─────────────────────────────────────────────

export type RetestVerdict = "fixed" | "still_present" | "regressed" | "new";

export interface RetestFindingVerdict {
  findingId: string | null;
  newFindingId: string | null;
  baseStatus: string | null;
  newStatus: string | null;
  severity: Severity | "none" | string | null;
  verdict: RetestVerdict;
}

export interface RetestInput {
  /** Retest the latest campaign on this target. */
  targetId?: string;
  /** Retest this specific base campaign. */
  campaignId?: string;
  /** Limit the verdict to these base findings. */
  findingIds?: string[];
  safeHarbor?: string;
}

export interface RetestLaunchResult {
  retestId: string;
  runId: string | null;
  baseCampaignId: string | null;
  targetId: string | null;
}

export interface RetestResult {
  retestId: string;
  baseCampaignId: string | null;
  newCampaignId: string | null;
  targetId: string | null;
  runId: string | null;
  status: "running" | "completed";
  verdictsSummary: { fixed: number; still_present: number; regressed: number; new: number };
  findings: RetestFindingVerdict[];
  edition: Edition;
}

// ── Evidence metadata (safe: counts/booleans, never content) ─────────────

export interface EvidenceMeta {
  vulnId: string;
  hasEvidence: boolean;
  counts: { commands: number; payloads: number; screenshots: number; logs: number; requests: number };
  /** First token of each command only — never full commands, values or output. */
  commandNames: string[];
  hasScreenshot: boolean;
  hasExtractedData: boolean;
  redacted: boolean;
}

// ── Metrics / time-series ────────────────────────────────────────────────

export type TimeseriesMetric = "severity" | "status" | "category" | "campaigns";
export type TimeseriesGroup = "campaign" | "day";

export interface TimeseriesQuery {
  metric?: TimeseriesMetric;
  group?: TimeseriesGroup;
  projectId?: string;
  targetId?: string;
  /** ISO date YYYY-MM-DD (campaign date). */
  from?: string;
  to?: string;
}

export interface TimeseriesPoint { t: string; value: number; }
export interface TimeseriesSeries { key: string; points: TimeseriesPoint[]; }
export interface TimeseriesResult { metric: string; group: string; series: TimeseriesSeries[]; edition: Edition; }

// ── Consolidated event stream ────────────────────────────────────────────

export interface DarkmoonEvent {
  event: string;
  contractVersion: string;
  seq: number;
  deliveryId: string | null;
  ts: string | null;
  /** Safe-field-only payload (ids, asset, severity, cvss, cwe/cve, mitre, status, counts, timestamps). */
  data: Record<string, unknown>;
}

export interface EventStreamOptions {
  /** Durable cursor: only events with seq greater than this are yielded. */
  since?: number;
  /** Event types to include (empty = all). */
  events?: string[];
  /** Poll interval for the graceful/poll transport (ms). Default 5000. */
  pollIntervalMs?: number;
  /** Abort the stream. */
  signal?: AbortSignal;
}

/** The complete v0.2.0 additive surface — implemented by both backends + facade. */
export interface DarkmoonClientExtensions {
  registerWebhook(input: WebhookInput): Promise<WebhookRegistration>;
  listWebhooks(): Promise<WebhookRegistration[]>;
  deleteWebhook(id: string): Promise<boolean>;
  launchRetest(input: RetestInput): Promise<RetestLaunchResult>;
  getRetest(id: string): Promise<RetestResult>;
  getEvidenceMeta(id: string): Promise<EvidenceMeta>;
  getTimeseries(query?: TimeseriesQuery): Promise<TimeseriesResult>;
  streamEvents(opts?: EventStreamOptions): AsyncIterable<DarkmoonEvent>;
}
