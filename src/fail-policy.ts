import type { Finding, Severity, SeveritySummary } from "./contract.js";
import { SEVERITIES } from "./contract.js";
import { normalizeSeverity } from "./normalize.js";

export interface FailPolicyResult {
  failed: boolean;
  /** Suggested process exit code: 0 pass, 2 policy fail (reserved: 1 = tool error). */
  exitCode: number;
  failOn: Severity[];
  /** Per-severity counts that tripped the policy. */
  offending: Partial<Record<Severity, number>>;
  reason: string;
}

/** Parse a --fail-on string like "critical,high" into a canonical severity set. */
export function parseFailOn(input: string | string[] | undefined): Severity[] {
  if (!input) return ["critical", "high"];
  const list = Array.isArray(input) ? input : input.split(",");
  const out = new Set<Severity>();
  for (const raw of list) {
    const t = raw.trim().toLowerCase();
    if (!t) continue;
    if (t === "none") return [];
    if (t === "all" || t === "any") return [...SEVERITIES];
    out.add(normalizeSeverity(t));
  }
  return [...out];
}

/**
 * Compute a fail/pass verdict from findings or a severity summary. This is the
 * ONLY source of CI pass/fail — never the pentest process exit code (which is 0
 * even with criticals).
 */
export function computeFailPolicy(
  input: SeveritySummary | Finding[],
  failOn: Severity[] | string | undefined,
): FailPolicyResult {
  const severities = Array.isArray(failOn) ? failOn : parseFailOn(failOn);
  const summary: SeveritySummary = Array.isArray(input) ? summarize(input) : input;
  const offending: Partial<Record<Severity, number>> = {};
  let failed = false;
  for (const sev of severities) {
    const n = summary[sev];
    if (n > 0) {
      offending[sev] = n;
      failed = true;
    }
  }
  const reason = failed
    ? `Fail policy tripped: ${Object.entries(offending)
        .map(([s, n]) => `${n} ${s}`)
        .join(", ")} (fail-on: ${severities.join(", ") || "none"}).`
    : `No findings at or above the fail threshold (fail-on: ${severities.join(", ") || "none"}).`;
  return { failed, exitCode: failed ? 2 : 0, failOn: severities, offending, reason };
}

function summarize(findings: Finding[]): SeveritySummary {
  const s: SeveritySummary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
  for (const f of findings) {
    s[f.severity] += 1;
    s.total += 1;
  }
  return s;
}
