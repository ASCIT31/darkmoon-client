/**
 * Secret hygiene + report/finding redaction.
 *
 * Threat model (plan §4): a Darkmoon report/finding rehydrates REAL values —
 * hosts, extracted data, credentials, tokens, JWTs, LLM keys, evidence bodies.
 * This module makes the DEFAULT client surface redaction-safe: severity counts,
 * titles, categories and metadata are exposed, but evidence bodies and any
 * secret-looking token are masked unless the caller makes a deliberate,
 * documented two-key opt-in ({ full: true, private: true }).
 *
 * NOTHING here is a security boundary against a determined caller — the raw data
 * is still reachable via the opt-in. Its job is to prevent ACCIDENTAL leakage
 * into CI logs, artifacts, editor panes and telemetry.
 */

/** Patterns for high-confidence secret material. Order matters (longest first). */
const SECRET_PATTERNS: Array<{ re: RegExp; label: string }> = [
  // JWT (three base64url segments)
  { re: /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b/g, label: "JWT" },
  // Common LLM / provider keys
  { re: /\bsk-(?:ant-|proj-|or-|live-)?[A-Za-z0-9_-]{16,}\b/g, label: "API_KEY" },
  { re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, label: "SLACK_TOKEN" },
  { re: /\bghp_[A-Za-z0-9]{20,}\b/g, label: "GITHUB_PAT" },
  { re: /\bglpat-[A-Za-z0-9_-]{16,}\b/g, label: "GITLAB_PAT" },
  { re: /\bAKIA[0-9A-Z]{16}\b/g, label: "AWS_KEY" },
  { re: /\bAIza[0-9A-Za-z_-]{30,}\b/g, label: "GOOGLE_KEY" },
  // Cryptolens-style license keys (grouped alnum blocks)
  { re: /\b[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b/g, label: "LICENSE_KEY" },
  // Bearer headers
  { re: /\bBearer\s+[A-Za-z0-9._-]{12,}/gi, label: "BEARER" },
  // Authorization / password / token key=value pairs in text
  { re: /\b(authorization|password|passwd|secret|token|api[_-]?key)\s*[:=]\s*["']?[^\s"',}]{6,}/gi, label: "CREDENTIAL" },
];

const MASK = "«REDACTED:$LABEL»";

/**
 * Mask secret-looking material in an arbitrary string. Safe for logs and CI output.
 */
export function scrubSecrets(input: string): string {
  if (!input) return input;
  let out = input;
  for (const { re, label } of SECRET_PATTERNS) {
    out = out.replace(re, (m) => {
      // Preserve the key name for key=value credentials so the message still reads.
      const eq = m.match(/^([A-Za-z_-]+)\s*[:=]/);
      const prefix = eq ? `${eq[1]}=` : "";
      return prefix + MASK.replace("$LABEL", label);
    });
  }
  return out;
}

/** Deep-scrub every string in a JSON-ish value (used before logging). */
export function scrubDeep<T>(value: T): T {
  if (typeof value === "string") return scrubSecrets(value) as unknown as T;
  if (Array.isArray(value)) return value.map((v) => scrubDeep(v)) as unknown as T;
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = scrubDeep(v);
    }
    return out as unknown as T;
  }
  return value;
}

/**
 * Redact a report body. In redacted mode we keep the structure/headings but blank
 * out fenced evidence blocks and scrub inline secrets. The full body (opt-in)
 * is returned verbatim by the caller and never passes through here.
 */
export function redactReport(markdown: string): string {
  if (!markdown) return markdown;
  // Blank the contents of fenced code blocks (raw requests/responses/payloads),
  // preserving the fences so the report still renders.
  const withoutFences = markdown.replace(/```[^\n]*\n[\s\S]*?```/g, (block) => {
    const firstLine = block.slice(0, block.indexOf("\n") + 1);
    return `${firstLine}«evidence redacted — use getReport({ full: true, private: true }) for the full report»\n\`\`\``;
  });
  return scrubSecrets(withoutFences);
}

/**
 * A crude heuristic: does a string look like it contains a live secret? Used to
 * hard-fail if a value we are about to return/log unexpectedly carries one.
 */
export function looksLikeSecret(input: string): boolean {
  if (!input) return false;
  return SECRET_PATTERNS.some(({ re }) => {
    re.lastIndex = 0;
    return re.test(input);
  });
}
