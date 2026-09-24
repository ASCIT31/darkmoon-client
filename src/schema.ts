/**
 * Lightweight runtime schema validation for the raw backend shapes, plus
 * version negotiation. We validate the SHAPES the client depends on (permissive:
 * unknown extra keys are allowed, matching the API's `additionalProperties:true`)
 * and fail clearly on the fields we actually read being wrong-typed or on an
 * unsupported backend version.
 */

import { z } from "zod";
import { SchemaInvalid, UnsupportedVersion } from "./errors.js";

/** Supported major contract/API versions. */
export const SUPPORTED_API_MAJORS = [1] as const;
export const SUPPORTED_OSS_SCHEMA = "1" as const;

const looseObject = z.object({}).passthrough();

/** Stats block on a campaign. */
export const StatsSchema = looseObject.extend({
  total_findings: z.number().optional(),
  critical: z.number().optional(),
  high: z.number().optional(),
  medium: z.number().optional(),
  low: z.number().optional(),
  info: z.number().optional(),
});

/** Raw campaign JSON (OSS on-disk == Pro API item). Permissive. */
export const RawCampaignSchema = looseObject.extend({
  id: z.string(),
  project_id: z.string().nullable().optional(),
  target_id: z.string().nullable().optional(),
  session_id: z.string().nullable().optional(),
  is_subagent: z.boolean().optional(),
  status: z.string().optional(),
  overall_risk: z.string().optional(),
  report_path: z.string().optional(),
  stats: StatsSchema.optional(),
});

/** Raw evidence block. */
export const RawEvidenceSchema = looseObject.extend({
  commands: z.array(z.any()).optional(),
  payloads: z.array(z.any()).optional(),
  raw_request: z.string().nullable().optional(),
  raw_response: z.string().nullable().optional(),
  extracted_data: z.any().optional(),
  logs: z.array(z.any()).optional(),
  explanation: z.string().nullable().optional(),
});

/** Raw vulnerability/finding JSON. Permissive. */
export const RawFindingSchema = looseObject.extend({
  id: z.string().optional(),
  node_id: z.string().optional(),
  title: z.string().nullable().optional(),
  severity: z.string().nullable().optional(),
  status: z.string().nullable().optional(),
  category: z.string().nullable().optional(),
  cve: z.string().nullable().optional(),
  campaign_id: z.string().nullable().optional(),
  evidence: RawEvidenceSchema.nullable().optional(),
});

export const RawFindingArraySchema = z.array(RawFindingSchema);

/** Pro root health payload (GET /). */
export const ProRootSchema = looseObject.extend({
  service: z.string().optional(),
  version: z.string().optional(),
  status: z.string().optional(),
});

export type RawCampaign = z.infer<typeof RawCampaignSchema>;
export type RawFinding = z.infer<typeof RawFindingSchema>;

export function parseCampaign(data: unknown): RawCampaign {
  const r = RawCampaignSchema.safeParse(data);
  if (!r.success) {
    throw new SchemaInvalid("Campaign JSON failed schema validation.", { issues: r.error.issues.slice(0, 5) });
  }
  return r.data;
}

export function parseFindings(data: unknown): RawFinding[] {
  // OSS files are a top-level array; Pro wraps in { data: [...] }.
  const arr = Array.isArray(data) ? data : (data as any)?.data;
  const r = RawFindingArraySchema.safeParse(arr);
  if (!r.success) {
    throw new SchemaInvalid("Findings JSON failed schema validation.", { issues: r.error.issues.slice(0, 5) });
  }
  return r.data;
}

/**
 * Parse a version string ("1.0.0", "v1.2", "1") into a major integer, or null.
 */
export function parseMajor(version: string | null | undefined): number | null {
  if (!version) return null;
  const m = String(version).match(/(\d+)/);
  return m ? Number(m[1]) : null;
}

/** Negotiate a Pro API version. Throws UnsupportedVersion on an unknown major. */
export function negotiateProVersion(version: string | null | undefined): { version: string; major: number } {
  const major = parseMajor(version);
  if (major === null) {
    // Unknown/absent version: accept but flag as best-effort (major 1 assumed).
    return { version: version ?? "unknown", major: 1 };
  }
  if (!(SUPPORTED_API_MAJORS as readonly number[]).includes(major)) {
    throw new UnsupportedVersion(
      `Darkmoon Pro API major v${major} is not supported by this client (supports v${SUPPORTED_API_MAJORS.join(", v")}).`,
      { version, supported: SUPPORTED_API_MAJORS },
    );
  }
  return { version: String(version), major };
}
