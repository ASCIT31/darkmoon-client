import { describe, it, expect, afterAll } from "vitest";
import { promises as fs } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { DarkmoonClient } from "../../src/index.js";
import type { Campaign, Finding } from "../../src/index.js";
import { startMockPro, type MockProServer } from "../helpers/mock-pro.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATAROOT = path.resolve(__dirname, "../../fixtures/dataroot");
const GOLDEN = path.resolve(__dirname, "../../fixtures/conformance");

const CAMPAIGN_IDS = ["camp_20260924_70602bf9", "camp_20260728_9018be77"];

function stripCampaign(c: Campaign) {
  const { raw: _r, edition: _e, ...rest } = c;
  return rest;
}
function stripFinding(f: Finding) {
  const { raw: _r, edition: _e, ...rest } = f;
  return rest;
}

let server: MockProServer | null = null;
afterAll(async () => {
  if (server) await server.close();
});

describe("cross-backend conformance: OSS == Pro == golden", () => {
  for (const id of CAMPAIGN_IDS) {
    it(`produces identical normalized objects for ${id}`, async () => {
      server = server ?? (await startMockPro());
      const oss = new DarkmoonClient({ mode: "oss", oss: { dataDir: DATAROOT, reportsDir: path.join(DATAROOT, "reports") } });
      const pro = new DarkmoonClient({ mode: "pro", pro: { baseUrl: server.url } });

      const ossCampaign = stripCampaign(await oss.getCampaign(id));
      const proCampaign = stripCampaign(await pro.getCampaign(id));
      const ossFindings = (await oss.listFindings({ campaignId: id })).map(stripFinding);
      const proFindings = (await pro.listFindings({ campaignId: id })).map(stripFinding);

      // 1) The two backends agree with each other.
      expect(proCampaign).toEqual(ossCampaign);
      expect(proFindings).toEqual(ossFindings);
      expect((await pro.getSeveritySummary(id))).toEqual(await oss.getSeveritySummary(id));

      // 2) Both agree with the committed language-neutral golden (Kotlin reuses it).
      const golden = JSON.parse(await fs.readFile(path.join(GOLDEN, `${id}.golden.json`), "utf8"));
      expect(ossCampaign).toEqual(golden.campaign);
      expect(proCampaign).toEqual(golden.campaign);
      expect(ossFindings).toEqual(golden.findings);
      expect(proFindings).toEqual(golden.findings);
      expect((await oss.getSeveritySummary(id))).toEqual(golden.severitySummary);
    });
  }
});
