/**
 * Typed error hierarchy. Every error carries a stable `code` so integrations can
 * branch on failure class without string-matching messages. Messages are always
 * secret-free.
 */

export type DarkmoonErrorCode =
  | "DARKMOON_NOT_AVAILABLE"
  | "AUTH_FAILED"
  | "LICENSE_INVALID"
  | "EDITION_MISMATCH"
  | "UNSUPPORTED_VERSION"
  | "REPORT_NOT_READY"
  | "CAMPAIGN_NOT_FOUND"
  | "FINDING_NOT_FOUND"
  | "CORRELATION_FAILED"
  | "TIMEOUT"
  | "STUCK_CAMPAIGN"
  | "NETWORK"
  | "SCHEMA_INVALID"
  | "INSECURE_DEFAULT"
  | "BAD_REQUEST"
  | "NOT_SUPPORTED";

export class DarkmoonError extends Error {
  readonly code: DarkmoonErrorCode;
  readonly details?: Record<string, unknown>;
  constructor(code: DarkmoonErrorCode, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = "DarkmoonError";
    this.code = code;
    this.details = details;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class DarkmoonNotAvailable extends DarkmoonError {
  constructor(message = "Darkmoon backend is not reachable (neither Pro API nor OSS CLI).", details?: Record<string, unknown>) {
    super("DARKMOON_NOT_AVAILABLE", message, details);
    this.name = "DarkmoonNotAvailable";
  }
}

export class AuthError extends DarkmoonError {
  constructor(message = "Authentication failed.", details?: Record<string, unknown>) {
    super("AUTH_FAILED", message, details);
    this.name = "AuthError";
  }
}

export class LicenseError extends DarkmoonError {
  constructor(message = "Darkmoon license is invalid or expired.", details?: Record<string, unknown>) {
    super("LICENSE_INVALID", message, details);
    this.name = "LicenseError";
  }
}

export class EditionMismatch extends DarkmoonError {
  constructor(message: string, details?: Record<string, unknown>) {
    super("EDITION_MISMATCH", message, details);
    this.name = "EditionMismatch";
  }
}

export class UnsupportedVersion extends DarkmoonError {
  constructor(message: string, details?: Record<string, unknown>) {
    super("UNSUPPORTED_VERSION", message, details);
    this.name = "UnsupportedVersion";
  }
}

export class ReportNotReady extends DarkmoonError {
  constructor(message = "The campaign report is not ready yet.", details?: Record<string, unknown>) {
    super("REPORT_NOT_READY", message, details);
    this.name = "ReportNotReady";
  }
}

export class CampaignNotFound extends DarkmoonError {
  constructor(message = "Campaign not found.", details?: Record<string, unknown>) {
    super("CAMPAIGN_NOT_FOUND", message, details);
    this.name = "CampaignNotFound";
  }
}

export class FindingNotFound extends DarkmoonError {
  constructor(message = "Finding not found.", details?: Record<string, unknown>) {
    super("FINDING_NOT_FOUND", message, details);
    this.name = "FindingNotFound";
  }
}

export class CorrelationFailed extends DarkmoonError {
  constructor(message = "Could not correlate the launched run to a campaign.", details?: Record<string, unknown>) {
    super("CORRELATION_FAILED", message, details);
    this.name = "CorrelationFailed";
  }
}

export class TimeoutError extends DarkmoonError {
  constructor(message = "Operation timed out.", details?: Record<string, unknown>) {
    super("TIMEOUT", message, details);
    this.name = "TimeoutError";
  }
}

export class StuckCampaignError extends DarkmoonError {
  constructor(message = "Campaign is stuck and did not reach a terminal state within the timeout.", details?: Record<string, unknown>) {
    super("STUCK_CAMPAIGN", message, details);
    this.name = "StuckCampaignError";
  }
}

export class NetworkError extends DarkmoonError {
  constructor(message = "Network error talking to the Darkmoon API.", details?: Record<string, unknown>) {
    super("NETWORK", message, details);
    this.name = "NetworkError";
  }
}

export class SchemaInvalid extends DarkmoonError {
  constructor(message = "Backend returned data that does not match the expected schema.", details?: Record<string, unknown>) {
    super("SCHEMA_INVALID", message, details);
    this.name = "SchemaInvalid";
  }
}

export class InsecureDefaultError extends DarkmoonError {
  constructor(message = "Backend is running with an insecure default (must_change_password / default secret).", details?: Record<string, unknown>) {
    super("INSECURE_DEFAULT", message, details);
    this.name = "InsecureDefaultError";
  }
}

export class NotSupported extends DarkmoonError {
  constructor(message: string, details?: Record<string, unknown>) {
    super("NOT_SUPPORTED", message, details);
    this.name = "NotSupported";
  }
}
