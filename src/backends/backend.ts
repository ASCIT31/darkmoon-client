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

/** Raw report fetch result before redaction policy is applied by the facade. */
export interface RawReport {
  campaignId: string;
  format: string;
  content: string;
  ready: boolean;
}

/**
 * A backend implements the mechanics for one edition. The DarkmoonClient facade
 * wraps a backend and applies the cross-cutting policy (redaction opt-in gating,
 * hard-timeout / stuck-campaign handling, warning surfacing).
 *
 * Backends return NORMALIZED contract objects so the conformance suite can assert
 * both produce identical output for the same underlying campaign.
 */
export interface Backend {
  readonly edition: "oss" | "pro";
  detect(): Promise<Capabilities>;
  launchCampaign(input: LaunchInput): Promise<LaunchResult>;
  /** Resolve the current state of a launched or referenced campaign. */
  getCampaignStatus(ref: CorrelationHandle | string): Promise<Campaign>;
  listCampaigns(filter?: CampaignFilter): Promise<Campaign[]>;
  getCampaign(id: string): Promise<Campaign>;
  listFindings(filter: FindingFilter, opts?: FindingReadOptions): Promise<Finding[]>;
  getFinding(id: string, opts?: FindingReadOptions): Promise<Finding>;
  /** Raw report (facade applies redaction). ready=false ⇒ placeholder/not-ready. */
  getReport(campaignId: string): Promise<RawReport>;
  /** Live progress. OSS emits a synthetic poll-based stream. */
  streamProgress(ref: CorrelationHandle | string): AsyncIterable<ProgressEvent>;
  /** Resolve a CorrelationHandle to a concrete campaign id (or null if not yet). */
  resolveCampaignId(ref: CorrelationHandle | string): Promise<string | null>;
}

/** Extract a campaign id string from any accepted reference shape. */
export function refToId(ref: CorrelationHandle | string): string | null {
  if (typeof ref === "string") return ref;
  return ref.campaignId ?? null;
}
