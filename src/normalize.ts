/**
 * Normalization: raw OSS/Pro JSON → canonical contract objects.
 *
 * Both backends store the SAME logical objects (the OSS reference and the Pro
 * API read the same on-disk JSON shape — see the Front-API OpenAPI annex), so a
 * single normalizer serves both. This is what guarantees the conformance
 * property: OssLocalBackend and ProHttpBackend produce identical Campaign /
 * Finding / SeveritySummary objects for the same underlying campaign.
 */

import type {
  Campaign,
  CampaignStatus,
  Edition,
  Finding,
  FindingEvidence,
  FindingStatus,
  Severity,
  SeveritySummary,
} from "./contract.js";
import { SEVERITIES } from "./contract.js";
import { redactEvidence } from "./redact-evidence.js";

/** Normalize any severity-ish string into the canonical lowercase set. */
export function normalizeSeverity(input: unknown): Severity {
  const s = String(input ?? "").trim().toLowerCase();
  switch (s) {
    case "critical":
    case "crit":
      return "critical";
    case "high":
    case "severe":
      return "high";
    case "medium":
    case "moderate":
    case "med":
      return "medium";
    case "low":
    case "minor":
      return "low";
    case "info":
    case "informational":
    case "information":
    case "none":
    case "":
      return "info";
    default:
      // Unknown value → conservative default of info (never silently "critical").
      return (SEVERITIES as readonly string[]).includes(s) ? (s as Severity) : "info";
  }
}

/** Normalize overall_risk into a severity or explicit "none". */
export function normalizeRisk(input: unknown): Severity | "none" {
  const s = String(input ?? "").trim().toLowerCase();
  if (s === "none" || s === "") return "none";
  return normalizeSeverity(s);
}

/** Normalize a finding status into the canonical set. */
export function normalizeFindingStatus(input: unknown): FindingStatus {
  const s = String(input ?? "").trim().toLowerCase();
  if (s.includes("remediat") || s.includes("fixed")) return "remediated";
  if (s.includes("exploit")) return "exploited";
  if (s.includes("confirm") && !s.includes("unconfirm")) return "confirmed";
  // "unconfirmed", "unconfirmed signal", "signal", "" → unconfirmed
  return "unconfirmed";
}

/** Normalize a campaign lifecycle status. */
export function normalizeCampaignStatus(input: unknown): CampaignStatus {
  const s = String(input ?? "").trim().toLowerCase();
  if (s.includes("complet") || s === "done" || s === "finished") return "completed";
  if (s.includes("run") || s === "in_progress" || s === "active") return "running";
  if (s === "queued" || s === "pending" || s === "scheduled") return "queued";
  if (s.includes("stop") || s === "cancelled" || s === "canceled" || s === "killed") return "stopped";
  if (s.includes("fail") || s.includes("error") || s === "crashed") return "failed";
  return "unknown";
}

function num(v: unknown): number {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

function str(v: unknown): string | null {
  if (v === null || v === undefined) return null;
  const s = String(v);
  return s.length ? s : null;
}

/**
 * Compute a severity summary from an explicit stats object OR by counting
 * findings. Findings are authoritative (the Pro API itself recomputes stats
 * from vulns because stored campaign.stats drift). Prefer findings when given.
 */
export function severitySummaryFromStats(stats: unknown): SeveritySummary {
  const s = (stats ?? {}) as Record<string, unknown>;
  const critical = num(s.critical);
  const high = num(s.high);
  const medium = num(s.medium);
  const low = num(s.low);
  const info = num(s.info);
  const total = s.total_findings !== undefined ? num(s.total_findings) : critical + high + medium + low + info;
  return { critical, high, medium, low, info, total };
}

export function severitySummaryFromFindings(findings: Array<{ severity: Severity }>): SeveritySummary {
  const sum: SeveritySummary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
  for (const f of findings) {
    sum[f.severity] += 1;
    sum.total += 1;
  }
  return sum;
}

/** Extract the target host/URL from a stored campaign or its report_path. */
function targetFromCampaign(raw: Record<string, unknown>): string | null {
  const direct = str(raw.target) ?? str(raw.host) ?? str((raw.target_stack as any)?.host);
  if (direct) return direct;
  // Fall back to the host embedded in report_path: pentest_report_<host>_<ts>.md
  const rp = str(raw.report_path);
  if (rp) {
    const m = rp.match(/pentest_report_(.+)_\d{8}-\d{4,6}\.md$/);
    if (m && m[1]) return m[1];
  }
  return null;
}

/** Normalize a raw campaign JSON object into the canonical Campaign. */
export function normalizeCampaign(raw: Record<string, unknown>, edition: Edition): Campaign {
  return {
    id: String(raw.id ?? ""),
    projectId: str(raw.project_id),
    targetId: str(raw.target_id),
    sessionId: str(raw.session_id),
    target: targetFromCampaign(raw),
    status: normalizeCampaignStatus(raw.status),
    overallRisk: normalizeRisk(raw.overall_risk),
    createdAt: str(raw.date) ?? str(raw.created_at),
    durationSeconds: raw.duration_seconds !== undefined ? num(raw.duration_seconds) : null,
    reportPath: str(raw.report_path),
    isSubagent: Boolean(raw.is_subagent),
    severity: severitySummaryFromStats(raw.stats),
    executiveSummary: str(raw.executive_summary),
    edition,
    raw,
  };
}

function evidenceFrom(raw: Record<string, unknown> | undefined | null, edition: Edition, includeEvidence: boolean, full: boolean): FindingEvidence | null {
  if (!includeEvidence || !raw) return null;
  const ev: FindingEvidence = {
    commands: Array.isArray(raw.commands) ? raw.commands.map(String) : [],
    payloads: Array.isArray(raw.payloads) ? raw.payloads.map(String) : [],
    rawRequest: str(raw.raw_request),
    rawResponse: str(raw.raw_response),
    extractedData: raw.extracted_data == null ? null : String(raw.extracted_data),
    logs: Array.isArray(raw.logs) ? raw.logs.map(String) : [],
    explanation: str(raw.explanation),
    redacted: false,
  };
  void edition;
  return full ? ev : redactEvidence(ev);
}

/** Normalize a raw vulnerability/finding JSON object into the canonical Finding. */
export function normalizeFinding(
  raw: Record<string, unknown>,
  edition: Edition,
  opts?: { includeEvidence?: boolean; full?: boolean },
): Finding {
  const includeEvidence = opts?.includeEvidence ?? false;
  const full = opts?.full ?? false;
  return {
    id: String(raw.id ?? raw.node_id ?? ""),
    campaignId: str(raw.campaign_id),
    projectId: str(raw.project_id),
    targetId: str(raw.target_id),
    title: str(raw.title),
    severity: normalizeSeverity(raw.severity),
    status: normalizeFindingStatus(raw.status),
    category: str(raw.category),
    cve: str(raw.cve),
    cvssScore: raw.cvss_score == null ? null : num(raw.cvss_score),
    cvssVector: str(raw.cvss_vector),
    mitreAttackId: str(raw.mitre_attack_id),
    mitreAttackName: str(raw.mitre_attack_name),
    endpoint: str(raw.endpoint),
    description: str(raw.description),
    remediation: typeof raw.remediation === "string" ? raw.remediation : str((raw.remediation as any)?.summary),
    discoveredByAgent: str(raw.discovered_by_agent),
    discoveredAt: str(raw.discovered_at),
    evidence: evidenceFrom(raw.evidence as Record<string, unknown> | undefined, edition, includeEvidence, full),
    edition,
    raw,
  };
}

/** Apply a finding filter (client-side; used by OSS and as a Pro safety net). */
export function matchesFindingFilter(f: Finding, filter: { severity?: string; category?: string; status?: string; campaignId?: string; projectId?: string; targetId?: string }): boolean {
  if (filter.campaignId && f.campaignId !== filter.campaignId) return false;
  if (filter.projectId && f.projectId !== filter.projectId) return false;
  if (filter.targetId && f.targetId !== filter.targetId) return false;
  if (filter.severity && f.severity !== normalizeSeverity(filter.severity)) return false;
  if (filter.status && f.status !== normalizeFindingStatus(filter.status)) return false;
  if (filter.category && f.category !== filter.category) return false;
  return true;
}
