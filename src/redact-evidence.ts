import type { FindingEvidence } from "./contract.js";
import { scrubSecrets } from "./redact.js";

/**
 * Redact a FindingEvidence object for the default (safe) surface. Raw request /
 * response / extracted data are the highest-risk fields (they carry rehydrated
 * real values), so they are dropped entirely; commands/payloads/logs are kept
 * but scrubbed of secret-looking tokens.
 */
export function redactEvidence(ev: FindingEvidence): FindingEvidence {
  return {
    commands: ev.commands.map(scrubSecrets),
    payloads: ev.payloads.map(scrubSecrets),
    rawRequest: ev.rawRequest ? "«redacted — opt in with { full: true, private: true }»" : null,
    rawResponse: ev.rawResponse ? "«redacted — opt in with { full: true, private: true }»" : null,
    extractedData: ev.extractedData ? "«redacted»" : null,
    logs: ev.logs.map(scrubSecrets),
    explanation: ev.explanation ? scrubSecrets(ev.explanation) : null,
    redacted: true,
  };
}
