import { describe, it, expect } from "vitest";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import {
  DarkmoonClient,
  computeRetestVerdicts,
  summarizeVerdicts,
  evidenceMetaFromFinding,
  type Finding,
  type DarkmoonEvent,
} from "../../src/index.js";
import { startMockPro } from "../helpers/mock-pro.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATAROOT = path.resolve(__dirname, "../../fixtures/dataroot");

function proClient(url: string) {
  return new DarkmoonClient({ mode: "pro", pro: { baseUrl: url, retries: 1, pageSize: 0 } });
}
function ossClient(extra: Record<string, unknown> = {}) {
  return new DarkmoonClient({ mode: "oss", oss: { dataDir: DATAROOT, reportsDir: path.join(DATAROOT, "reports"), ...extra } });
}
function finding(over: Partial<Finding>): Finding {
  return {
    id: "f", campaignId: null, projectId: null, targetId: null, title: "T", severity: "high",
    status: "confirmed", category: "c", cve: null, cvssScore: null, cvssVector: null,
    mitreAttackId: null, mitreAttackName: null, endpoint: "/e", description: null, remediation: null,
    discoveredByAgent: null, discoveredAt: null, evidence: null, edition: "pro", ...over,
  };
}

// ───────────────────────── Pro (mock server) ─────────────────────────

describe("v0.2.0 Pro — webhooks", () => {
  it("registers (secret once), lists (masked), tests, and deletes", async () => {
    const srv = await startMockPro({ systemInfo: true });
    try {
      const c = proClient(srv.url);
      const reg = await c.registerWebhook({ url: "https://splunk:8088/services/collector/event", events: ["finding.exploited"] });
      expect(reg.id).toMatch(/^wh_/);
      expect(reg.secret && !reg.secret.startsWith("set:")).toBe(true);

      const list = await c.listWebhooks();
      expect(list[0]!.secret?.startsWith("set:")).toBe(true);

      expect(await c.deleteWebhook(reg.id)).toBe(true);
      expect(await c.deleteWebhook("wh_missing")).toBe(false);
    } finally {
      await srv.close();
    }
  });

  it("rejects an invalid webhook url with BAD_REQUEST", async () => {
    const srv = await startMockPro({ systemInfo: true });
    try {
      await expect(proClient(srv.url).registerWebhook({ url: "ftp://nope" })).rejects.toMatchObject({ code: "BAD_REQUEST" });
    } finally {
      await srv.close();
    }
  });
});

describe("v0.2.0 Pro — retest", () => {
  it("launches and maps derived verdicts + summary", async () => {
    const srv = await startMockPro({ systemInfo: true });
    try {
      const c = proClient(srv.url);
      const launched = await c.launchRetest({ campaignId: "camp_base" });
      expect(launched.retestId).toBe("retest_abc123");

      const r = await c.getRetest("retest_abc123");
      expect(r.status).toBe("completed");
      expect(r.verdictsSummary).toEqual({ fixed: 1, still_present: 1, regressed: 1, new: 1 });
      expect(r.findings.map((f) => f.verdict).sort()).toEqual(["fixed", "new", "regressed", "still_present"]);
      expect(r.edition).toBe("pro");
    } finally {
      await srv.close();
    }
  });

  it("launchRetest without target/campaign is BAD_REQUEST (facade guard)", async () => {
    const srv = await startMockPro({ systemInfo: true });
    try {
      await expect(proClient(srv.url).launchRetest({})).rejects.toMatchObject({ code: "BAD_REQUEST" });
    } finally {
      await srv.close();
    }
  });
});

describe("v0.2.0 Pro — evidence-meta + timeseries", () => {
  it("maps evidence metadata (counts only, no content)", async () => {
    const srv = await startMockPro({ systemInfo: true });
    try {
      const meta = await proClient(srv.url).getEvidenceMeta("vuln_59058f");
      expect(meta.redacted).toBe(true);
      expect(meta.counts.commands).toBeGreaterThan(0);
      expect(meta.commandNames).toContain("curl");
      // safe by construction: only counts/booleans/command-names — no evidence bodies
      expect(Object.keys(meta).sort()).toEqual(
        ["commandNames", "counts", "hasEvidence", "hasExtractedData", "hasScreenshot", "redacted", "vulnId"],
      );
    } finally {
      await srv.close();
    }
  });

  it("maps a timeseries and honours pageSize cap", async () => {
    const srv = await startMockPro({ systemInfo: true });
    try {
      const ts = await proClient(srv.url).getTimeseries({ metric: "severity", group: "day" });
      expect(ts.series[0]!.key).toBe("critical");
      expect(ts.series[0]!.points.length).toBe(2);

      const capped = new DarkmoonClient({ mode: "pro", pro: { baseUrl: srv.url, pageSize: 0 } });
      const all = await capped.getTimeseries({ metric: "severity" });
      expect(all.series.length).toBe(1);
    } finally {
      await srv.close();
    }
  });

  it("rejects a bad metric with BAD_REQUEST", async () => {
    const srv = await startMockPro({ systemInfo: true });
    try {
      // @ts-expect-error deliberately invalid metric
      await expect(proClient(srv.url).getTimeseries({ metric: "bogus" })).rejects.toMatchObject({ code: "BAD_REQUEST" });
    } finally {
      await srv.close();
    }
  });
});

describe("v0.2.0 Pro — event stream (SSE)", () => {
  it("yields normalized events and filters by type + cursor", async () => {
    const srv = await startMockPro({ systemInfo: true });
    try {
      const c = proClient(srv.url);
      const all: DarkmoonEvent[] = [];
      for await (const e of c.streamEvents({ since: 0 })) all.push(e);
      expect(all.map((e) => e.event)).toEqual(["campaign.started", "finding.exploited", "campaign.completed"]);
      expect(all[0]!.contractVersion).toBe("1");

      const filtered: DarkmoonEvent[] = [];
      for await (const e of c.streamEvents({ since: 1, events: ["campaign.completed"] })) filtered.push(e);
      expect(filtered).toHaveLength(1);
      expect(filtered[0]!.event).toBe("campaign.completed");
      expect(filtered[0]!.seq).toBe(3);
    } finally {
      await srv.close();
    }
  });
});

// ───────────────────────── OSS (graceful degradation) ─────────────────

describe("v0.2.0 OSS — degradation", () => {
  it("webhooks throw NOT_SUPPORTED (OSS has no server)", async () => {
    const c = ossClient();
    await expect(c.registerWebhook({ url: "https://x" })).rejects.toMatchObject({ code: "NOT_SUPPORTED" });
    await expect(c.listWebhooks()).rejects.toMatchObject({ code: "NOT_SUPPORTED" });
  });

  it("computes evidence-meta client-side from the fixture finding", async () => {
    const meta = await ossClient().getEvidenceMeta("vuln_59058f");
    expect(meta.vulnId).toBe("vuln_59058f");
    expect(meta.hasEvidence).toBe(true);
    expect(meta.redacted).toBe(true);
    expect(meta.counts.commands).toBeGreaterThan(0);
    // never surfaces raw evidence content
    expect(JSON.stringify(meta)).not.toMatch(/BEGIN|password|secret|Bearer/i);
  });

  it("computes a timeseries client-side from fixture campaigns/findings", async () => {
    const ts = await ossClient().getTimeseries({ metric: "severity", group: "day" });
    expect(ts.edition).toBe("oss");
    const keys = ts.series.map((s) => s.key);
    expect(keys).toContain("critical");
  });

  it("launchRetest resolves the base campaign and returns a tracked handle", async () => {
    // Use a harmless launch template so no real scanner spawns.
    const c = ossClient({ launchTemplate: ["true", "{PROMPT}"] });
    const launched = await c.launchRetest({ campaignId: "camp_20260924_70602bf9" });
    expect(launched.retestId).toMatch(/^retest_/);
    expect(launched.baseCampaignId).toBe("camp_20260924_70602bf9");
    const r = await c.getRetest(launched.retestId);
    expect(r.baseCampaignId).toBe("camp_20260924_70602bf9");
    expect(["running", "completed"]).toContain(r.status);
  });

  it("streamEvents baseline yields nothing then can be aborted", async () => {
    const c = ossClient();
    const ctrl = new AbortController();
    const seen: DarkmoonEvent[] = [];
    setTimeout(() => ctrl.abort(), 120);
    for await (const e of c.streamEvents({ pollIntervalMs: 40, signal: ctrl.signal })) seen.push(e);
    expect(seen).toEqual([]); // baseline pass emits nothing; no state changes during the window
  });
});

// ───────────────────────── Pure verdict engine ────────────────────────

describe("v0.2.0 verdict engine (shared, edition-neutral)", () => {
  it("classifies fixed / still_present / regressed / new", () => {
    const base = [
      finding({ id: "a", title: "SQLi", endpoint: "/login", category: "inj", status: "confirmed" }),
      finding({ id: "b", title: "XSS", endpoint: "/s", category: "xss", status: "confirmed" }),
      finding({ id: "c", title: "Redirect", endpoint: "/go", category: "redir", status: "remediated" }),
    ];
    const next = [
      finding({ id: "a2", title: "SQLi", endpoint: "/login", category: "inj", status: "exploited" }),
      finding({ id: "c2", title: "Redirect", endpoint: "/go", category: "redir", status: "confirmed" }),
      finding({ id: "d2", title: "SSRF", endpoint: "/f", category: "ssrf", status: "confirmed" }),
    ];
    const verdicts = computeRetestVerdicts(base, next);
    const by = Object.fromEntries(verdicts.filter((v) => v.findingId).map((v) => [v.findingId, v.verdict]));
    expect(by.a).toBe("still_present");
    expect(by.b).toBe("fixed");
    expect(by.c).toBe("regressed");
    expect(verdicts.find((v) => v.verdict === "new")?.newFindingId).toBe("d2");
    expect(summarizeVerdicts(verdicts)).toEqual({ fixed: 1, still_present: 1, regressed: 1, new: 1 });
  });

  it("evidenceMetaFromFinding never leaks content", () => {
    const f = finding({
      evidence: { commands: ["curl http://x -H 'Authorization: Bearer S3CRET'"], payloads: ["' OR 1=1"], rawRequest: "GET /", rawResponse: "500", extractedData: "leak", logs: ["l"], explanation: "e", redacted: true },
    });
    const meta = evidenceMetaFromFinding("vX", f);
    expect(meta.counts.commands).toBe(1);
    expect(meta.commandNames).toEqual(["curl"]);
    expect(meta.hasExtractedData).toBe(true);
    expect(JSON.stringify(meta)).not.toMatch(/S3CRET|leak|OR 1=1/);
  });
});
