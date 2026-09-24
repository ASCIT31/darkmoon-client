import { describe, it, expect } from "vitest";
import {
  normalizeSeverity,
  normalizeFindingStatus,
  normalizeCampaignStatus,
  normalizeRisk,
  severitySummaryFromFindings,
  severitySummaryFromStats,
} from "../../src/index.js";

describe("normalizeSeverity", () => {
  it("maps canonical + synonyms to the lowercase set", () => {
    expect(normalizeSeverity("CRITICAL")).toBe("critical");
    expect(normalizeSeverity("High")).toBe("high");
    expect(normalizeSeverity("moderate")).toBe("medium");
    expect(normalizeSeverity("informational")).toBe("info");
    expect(normalizeSeverity("minor")).toBe("low");
  });
  it("never silently escalates unknown values to critical", () => {
    expect(normalizeSeverity("weird")).toBe("info");
    expect(normalizeSeverity(null)).toBe("info");
    expect(normalizeSeverity(undefined)).toBe("info");
  });
});

describe("normalizeFindingStatus", () => {
  it("normalizes to the canonical status set", () => {
    expect(normalizeFindingStatus("exploited")).toBe("exploited");
    expect(normalizeFindingStatus("CONFIRMED")).toBe("confirmed");
    expect(normalizeFindingStatus("UNCONFIRMED SIGNAL")).toBe("unconfirmed");
    expect(normalizeFindingStatus("remediated")).toBe("remediated");
    expect(normalizeFindingStatus("")).toBe("unconfirmed");
  });
});

describe("normalizeCampaignStatus", () => {
  it("maps lifecycle synonyms", () => {
    expect(normalizeCampaignStatus("completed")).toBe("completed");
    expect(normalizeCampaignStatus("in_progress")).toBe("running");
    expect(normalizeCampaignStatus("killed")).toBe("stopped");
    expect(normalizeCampaignStatus("error")).toBe("failed");
    expect(normalizeCampaignStatus("scheduled")).toBe("queued");
    expect(normalizeCampaignStatus("???")).toBe("unknown");
  });
});

describe("normalizeRisk", () => {
  it("keeps none explicit", () => {
    expect(normalizeRisk("none")).toBe("none");
    expect(normalizeRisk("")).toBe("none");
    expect(normalizeRisk("critical")).toBe("critical");
  });
});

describe("severity summaries", () => {
  it("counts from findings", () => {
    const s = severitySummaryFromFindings([
      { severity: "critical" },
      { severity: "critical" },
      { severity: "high" },
      { severity: "low" },
    ]);
    expect(s).toEqual({ critical: 2, high: 1, medium: 0, low: 1, info: 0, total: 4 });
  });
  it("reads from stats and derives total when absent", () => {
    expect(severitySummaryFromStats({ critical: 1, high: 2 })).toEqual({ critical: 1, high: 2, medium: 0, low: 0, info: 0, total: 3 });
    expect(severitySummaryFromStats({ total_findings: 9, critical: 1 }).total).toBe(9);
  });
});
