// Generates language-neutral golden normalized objects from the OSS fixtures.
// The Kotlin (JetBrains) client reuses these exact goldens for its own
// conformance suite. Run: node scripts/gen-golden.mjs
import { promises as fs } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { OssLocalBackend } from "../dist/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATAROOT = path.resolve(__dirname, "../fixtures/dataroot");
const OUT = path.resolve(__dirname, "../fixtures/conformance");

const CAMPAIGN_IDS = ["camp_20260924_70602bf9", "camp_20260728_9018be77"];

function strip(o) {
  const { raw: _r, edition: _e, ...rest } = o;
  return rest;
}

const be = new OssLocalBackend({ dataDir: DATAROOT, reportsDir: path.join(DATAROOT, "reports") });
await fs.mkdir(OUT, { recursive: true });

for (const id of CAMPAIGN_IDS) {
  const campaign = strip(await be.getCampaign(id));
  const findings = (await be.listFindings({ campaignId: id })).map(strip);
  const summary = (await be.getCampaign(id)).severity;
  const golden = { contractVersion: "1.0.0", campaign, severitySummary: summary, findings };
  await fs.writeFile(path.join(OUT, `${id}.golden.json`), JSON.stringify(golden, null, 2) + "\n");
  console.log(`golden written: ${id} (${findings.length} findings, total=${summary.total})`);
}
