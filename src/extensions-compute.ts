/**
 * Client-side computation for the v0.2.0 additive surface, used by the OSS
 * backend (which has no server) to degrade gracefully: evidence-metadata and
 * retest verdicts are derived from normalized Findings exactly as the Pro server
 * derives them, so the conformance guarantee holds across editions.
 */
import type { Finding } from "./contract.js";
import type { EvidenceMeta, RetestFindingVerdict } from "./extensions.js";

/** Finding statuses treated as "closed" (mirror the Pro _is_open_vulnerability set). */
const CLOSED = new Set(["remediated", "resolved", "closed", "fixed"]);

function norm(s: unknown): string {
  return String(s ?? "").trim().toLowerCase();
}

/** Stable cross-campaign identity of a finding: title|endpoint|category. */
export function findingKey(f: Finding): string {
  return [norm(f.title), norm(f.endpoint), norm(f.category)].join("|");
}

/** Compute safe evidence metadata from a (redacted) Finding — never leaks content. */
export function evidenceMetaFromFinding(vulnId: string, f: Finding | null): EvidenceMeta {
  const ev = f?.evidence ?? null;
  const commands = ev?.commands ?? [];
  const payloads = ev?.payloads ?? [];
  const logs = ev?.logs ?? [];
  const requestCount = (ev?.rawRequest ? 1 : 0) + (ev?.rawResponse ? 1 : 0);
  const commandNames = commands
    .map((c) => norm(c).split(/\s+/)[0] ?? "")
    .filter(Boolean)
    .slice(0, 50);
  return {
    vulnId,
    hasEvidence: Boolean(ev),
    counts: {
      commands: commands.length,
      payloads: payloads.length,
      screenshots: 0, // OSS evidence has no dedicated screenshot list in the normalized shape
      logs: logs.length,
      requests: requestCount,
    },
    commandNames: Array.from(new Set(commandNames)),
    hasScreenshot: false,
    hasExtractedData: Boolean(ev?.extractedData),
    redacted: true,
  };
}

/** Diff base vs new findings → per-finding verdicts (same rules as the Pro server). */
export function computeRetestVerdicts(
  base: Finding[],
  next: Finding[],
  findingIds?: string[],
): RetestFindingVerdict[] {
  let baseSet = base;
  if (findingIds?.length) {
    const wanted = new Set(findingIds);
    baseSet = base.filter((f) => f.id && wanted.has(f.id));
  }
  const nextByKey = new Map<string, Finding>();
  for (const f of next) if (!nextByKey.has(findingKey(f))) nextByKey.set(findingKey(f), f);

  const results: RetestFindingVerdict[] = [];
  const baseKeys = new Set<string>();
  for (const f of baseSet) {
    const key = findingKey(f);
    baseKeys.add(key);
    const baseStatus = norm(f.status) || "unconfirmed";
    const match = nextByKey.get(key);
    if (match) {
      results.push({
        findingId: f.id ?? null,
        newFindingId: match.id ?? null,
        baseStatus,
        newStatus: norm(match.status) || "unconfirmed",
        severity: match.severity ?? f.severity ?? null,
        verdict: CLOSED.has(baseStatus) ? "regressed" : "still_present",
      });
    } else {
      results.push({
        findingId: f.id ?? null,
        newFindingId: null,
        baseStatus,
        newStatus: null,
        severity: f.severity ?? null,
        verdict: "fixed",
      });
    }
  }
  for (const f of next) {
    if (!baseKeys.has(findingKey(f))) {
      results.push({
        findingId: null,
        newFindingId: f.id ?? null,
        baseStatus: null,
        newStatus: norm(f.status) || "unconfirmed",
        severity: f.severity ?? null,
        verdict: "new",
      });
    }
  }
  return results;
}

/** Roll a verdict list into the {fixed,still_present,regressed,new} summary. */
export function summarizeVerdicts(
  findings: RetestFindingVerdict[],
): { fixed: number; still_present: number; regressed: number; new: number } {
  const summary = { fixed: 0, still_present: 0, regressed: 0, new: 0 };
  for (const f of findings) summary[f.verdict] += 1;
  return summary;
}
