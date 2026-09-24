/**
 * @darkmoon/client — public entry point.
 *
 * The FROZEN contract lives in ./contract. The 5 official integrations import
 * ONLY from this package root. See CONTRACT.md for the linkable API surface.
 */

export { DarkmoonClient, type DarkmoonClientConfig } from "./client.js";
export { ProHttpBackend, type ProHttpConfig } from "./backends/pro-http.js";
export { OssLocalBackend, type OssLocalConfig } from "./backends/oss-local.js";
export type { Backend, RawReport } from "./backends/backend.js";

export {
  CONTRACT_VERSION,
  SEVERITIES,
  FINDING_STATUSES,
  CAMPAIGN_STATUSES,
} from "./contract.js";
export type {
  Severity,
  FindingStatus,
  CampaignStatus,
  Edition,
  ClientMode,
  Capabilities,
  SeveritySummary,
  Campaign,
  Finding,
  FindingEvidence,
  Report,
  ProgressEvent,
  LaunchInput,
  LaunchResult,
  CorrelationHandle,
  CampaignRef,
  WaitOptions,
  CampaignFilter,
  FindingFilter,
  ReportOptions,
  FindingReadOptions,
  DarkmoonClientContract,
} from "./contract.js";

export {
  computeFailPolicy,
  parseFailOn,
  type FailPolicyResult,
} from "./fail-policy.js";

export {
  normalizeSeverity,
  normalizeFindingStatus,
  normalizeCampaignStatus,
  normalizeRisk,
  normalizeCampaign,
  normalizeFinding,
  severitySummaryFromStats,
  severitySummaryFromFindings,
} from "./normalize.js";

export {
  scrubSecrets,
  scrubDeep,
  redactReport,
  looksLikeSecret,
} from "./redact.js";

export {
  parseCampaign,
  parseFindings,
  negotiateProVersion,
  parseMajor,
  SUPPORTED_API_MAJORS,
} from "./schema.js";

export { Logger, type LogLevel } from "./util/logger.js";

export {
  DarkmoonError,
  DarkmoonNotAvailable,
  AuthError,
  LicenseError,
  EditionMismatch,
  UnsupportedVersion,
  ReportNotReady,
  CampaignNotFound,
  FindingNotFound,
  CorrelationFailed,
  TimeoutError,
  StuckCampaignError,
  NetworkError,
  SchemaInvalid,
  InsecureDefaultError,
  NotSupported,
  type DarkmoonErrorCode,
} from "./errors.js";
