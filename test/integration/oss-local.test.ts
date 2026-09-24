import { describe, it, expect } from "vitest";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { DarkmoonClient, OssLocalBackend, CampaignNotFound, FindingNotFound } from "../../src/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATAROOT = path.resolve(__dirname, "../../fixtures/dataroot");

function ossClient() {
  return new DarkmoonClient({ mode: "oss", oss: { dataDir: DATAROOT, reportsDir: path.join(DATAROOT, "reports") } });
}

describe("OssLocalBackend (real fixture JSON tree)", () => {
  it("detects the OSS edition", async () => {
    const caps = await ossClient().detect();
    expect(caps.edition).toBe("oss");
    expect(caps.features.restApi).toBe(false);
  });

  it("lists campaigns and excludes sub-agent artefacts", async () => {
    const list = await ossClient().listCampaigns();
    const ids = list.map((c) => c.id);
    expect(ids).toContain("camp_20260924_70602bf9");
    expect(ids).not.toContain("camp_sub");
  });

  it("reads a campaign and recomputes severity from findings", async () => {
    const c = await ossClient().getCampaign("camp_20260924_70602bf9");
    expect(c.status).toBe("completed");
    expect(c.severity.total).toBe(5);
    expect(c.severity.critical).toBe(2);
    expect(c.target).toBe("127.0.0.1:3000");
  });

  it("lists findings redaction-safe by default (no evidence)", async () => {
    const findings = await ossClient().listFindings({ campaignId: "camp_20260924_70602bf9" });
    expect(findings.length).toBe(5);
    expect(findings.every((f) => f.evidence === null)).toBe(true);
    expect(findings.every((f) => ["critical", "high", "medium", "low", "info"].includes(f.severity))).toBe(true);
  });

  it("includes redacted evidence on explicit request; strips raw request/response", async () => {
    const findings = await ossClient().listFindings({ campaignId: "camp_20260924_70602bf9" }, { includeEvidence: true });
    const withEv = findings.find((f) => f.evidence);
    expect(withEv?.evidence?.redacted).toBe(true);
    expect(withEv?.evidence?.rawResponse === null || withEv?.evidence?.rawResponse?.includes("redacted")).toBe(true);
  });

  it("getSeveritySummary matches counted findings", async () => {
    const s = await ossClient().getSeveritySummary("camp_20260924_70602bf9");
    expect(s.total).toBe(5);
  });

  it("returns a redacted report and blanks evidence blocks", async () => {
    const rep = await ossClient().getReport("camp_20260924_70602bf9");
    expect(rep.ready).toBe(true);
    expect(rep.redacted).toBe(true);
    expect(rep.content).toContain("evidence redacted");
  });

  it("full report requires the two-key opt-in", async () => {
    const rep = await ossClient().getReport("camp_20260924_70602bf9", { full: true, private: true });
    expect(rep.redacted).toBe(false);
    expect(rep.content.length).toBeGreaterThan(1000);
  });

  it("throws CampaignNotFound / FindingNotFound for missing ids", async () => {
    await expect(ossClient().getCampaign("camp_missing")).rejects.toBeInstanceOf(CampaignNotFound);
    const be = new OssLocalBackend({ dataDir: DATAROOT });
    await expect(be.getFinding("does-not-exist")).rejects.toBeInstanceOf(FindingNotFound);
  });

  it("resolves a correlation handle to the single new campaign since launch", async () => {
    const be = new OssLocalBackend({ dataDir: DATAROOT });
    // Pretend everything except 70602bf9 pre-existed → it is the 'new' one.
    const handle = {
      edition: "oss" as const,
      runId: null,
      campaignId: null,
      nonce: "ci-test",
      preCampaignIds: ["camp_20260728_9018be77", "camp_noreport", "camp_stuck", "camp_sub"],
      startedAtMs: 0, // fixtures are older; use 0 so mtime>=start passes
    };
    const id = await be.resolveCampaignId(handle);
    expect(id).toBe("camp_20260924_70602bf9");
  });
});
