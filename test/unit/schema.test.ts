import { describe, it, expect } from "vitest";
import { parseCampaign, parseFindings, negotiateProVersion, parseMajor, UnsupportedVersion, SchemaInvalid } from "../../src/index.js";

describe("parseCampaign", () => {
  it("accepts a valid loose campaign with extra keys", () => {
    const c = parseCampaign({ id: "camp_x", status: "completed", extra: 1, stats: { critical: 1 } });
    expect(c.id).toBe("camp_x");
  });
  it("rejects a campaign missing id", () => {
    expect(() => parseCampaign({ status: "completed" })).toThrow(SchemaInvalid);
  });
});

describe("parseFindings", () => {
  it("accepts a top-level array (OSS) and a wrapped {data} (Pro)", () => {
    expect(parseFindings([{ id: "v1", severity: "critical" }])).toHaveLength(1);
    expect(parseFindings({ data: [{ id: "v1" }, { id: "v2" }] })).toHaveLength(2);
  });
});

describe("version negotiation", () => {
  it("parses majors", () => {
    expect(parseMajor("1.0.0")).toBe(1);
    expect(parseMajor("v2.3")).toBe(2);
    expect(parseMajor(null)).toBe(null);
  });
  it("accepts supported major", () => {
    expect(negotiateProVersion("1.0.0").major).toBe(1);
  });
  it("accepts unknown version best-effort", () => {
    expect(negotiateProVersion("unknown").version).toBe("unknown");
  });
  it("rejects an unsupported major", () => {
    expect(() => negotiateProVersion("9.9.9")).toThrow(UnsupportedVersion);
  });
});
