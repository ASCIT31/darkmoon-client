import { describe, it, expect } from "vitest";
import { computeFailPolicy, parseFailOn, type SeveritySummary } from "../../src/index.js";

const sum = (o: Partial<SeveritySummary>): SeveritySummary => ({ critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0, ...o });

describe("parseFailOn", () => {
  it("defaults to critical,high", () => {
    expect(parseFailOn(undefined)).toEqual(["critical", "high"]);
  });
  it("parses csv and normalizes", () => {
    expect(parseFailOn("critical, High ,medium")).toEqual(["critical", "high", "medium"]);
  });
  it("supports none and all", () => {
    expect(parseFailOn("none")).toEqual([]);
    expect(parseFailOn("all")).toEqual(["critical", "high", "medium", "low", "info"]);
  });
});

describe("computeFailPolicy", () => {
  it("fails when an offending severity is present", () => {
    const r = computeFailPolicy(sum({ critical: 1, total: 1 }), "critical,high");
    expect(r.failed).toBe(true);
    expect(r.exitCode).toBe(2);
    expect(r.offending).toEqual({ critical: 1 });
  });
  it("passes when nothing meets the threshold", () => {
    const r = computeFailPolicy(sum({ medium: 3, total: 3 }), "critical,high");
    expect(r.failed).toBe(false);
    expect(r.exitCode).toBe(0);
  });
  it("with fail-on none always passes", () => {
    expect(computeFailPolicy(sum({ critical: 9, total: 9 }), "none").failed).toBe(false);
  });
  it("computes from a findings array", () => {
    const findings = [
      { severity: "critical" },
      { severity: "low" },
    ] as any;
    const r = computeFailPolicy(findings, "critical");
    expect(r.failed).toBe(true);
  });
});
