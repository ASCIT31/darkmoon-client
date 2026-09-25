import { describe, it, expect } from "vitest";
import { DarkmoonClient } from "../../src/index.js";
import { ReportNotReady, StuckCampaignError, DarkmoonError } from "../../src/index.js";
import type { Backend, RawReport } from "../../src/backends/backend.js";
import type { Campaign, Finding } from "../../src/index.js";

function campaign(over: Partial<Campaign>): Campaign {
  return {
    id: "camp_test",
    projectId: null,
    targetId: null,
    sessionId: null,
    target: null,
    status: "completed",
    overallRisk: "critical",
    createdAt: null,
    durationSeconds: null,
    reportPath: null,
    isSubagent: false,
    severity: { critical: 1, high: 0, medium: 0, low: 0, info: 0, total: 1 },
    executiveSummary: null,
    edition: "pro",
    ...over,
  };
}

class FakeBackend implements Backend {
  readonly edition = "pro" as const;
  statuses: Campaign[] = [];
  private i = 0;
  report: RawReport = { campaignId: "camp_test", format: "markdown", content: "# Real report\nbody", ready: true };
  constructor(init?: Partial<FakeBackend>) {
    Object.assign(this, init);
  }
  async detect() {
    return { edition: "pro" as const, mode: "pro" as const, version: "1.0.0", available: true, features: { restApi: true, streaming: true, auth: true, remediation: true, dashboard: true, scheduler: true }, detectedBy: "override" as const, warnings: [] };
  }
  async launchCampaign() {
    return { correlation: { edition: "pro" as const, runId: "run_x", campaignId: null, nonce: "ci-x", startedAtMs: Date.now() }, campaignId: null, runId: "run_x" };
  }
  async getCampaignStatus() {
    const c = this.statuses[Math.min(this.i, this.statuses.length - 1)] ?? campaign({});
    this.i++;
    return c;
  }
  async listCampaigns() {
    return [];
  }
  async getCampaign() {
    return campaign({});
  }
  async listFindings(): Promise<Finding[]> {
    return [];
  }
  async getFinding(): Promise<Finding> {
    throw new Error("nope");
  }
  async getReport() {
    return this.report;
  }
  async *streamProgress() {
    yield { type: "run_completed", terminal: true };
  }
  async resolveCampaignId() {
    return "camp_test";
  }
  // v0.2.0 additive surface (stubs — exercised in extensions tests, not here)
  async registerWebhook() {
    return { id: "wh_x", url: "http://x", events: [], format: "darkmoon", enabled: true, createdAt: null };
  }
  async listWebhooks() {
    return [];
  }
  async deleteWebhook() {
    return true;
  }
  async launchRetest() {
    return { retestId: "retest_x", runId: "run_x", baseCampaignId: "camp_test", targetId: null };
  }
  async getRetest() {
    return { retestId: "retest_x", baseCampaignId: "camp_test", newCampaignId: null, targetId: null, runId: "run_x", status: "running" as const, verdictsSummary: { fixed: 0, still_present: 0, regressed: 0, new: 0 }, findings: [], edition: "pro" as const };
  }
  async getEvidenceMeta() {
    return { vulnId: "v", hasEvidence: false, counts: { commands: 0, payloads: 0, screenshots: 0, logs: 0, requests: 0 }, commandNames: [], hasScreenshot: false, hasExtractedData: false, redacted: true };
  }
  async getTimeseries() {
    return { metric: "severity", group: "day", series: [], edition: "pro" as const };
  }
  async *streamEvents() {
    // no events in the fake
  }
}

function clientWith(be: Backend): DarkmoonClient {
  const c = new DarkmoonClient({ mode: "pro", pro: { baseUrl: "http://unused" } });
  // Inject the fake backend directly.
  (c as any).backend = be;
  (c as any).caps = { edition: "pro" };
  return c;
}

describe("report redaction opt-in", () => {
  it("returns a redacted report by default", async () => {
    const c = clientWith(new FakeBackend({ report: { campaignId: "camp_test", format: "markdown", content: "## F\np\n\n```\nBearer eyJa.b.c\n```\n", ready: true } }));
    const rep = await c.getReport("camp_test");
    expect(rep.redacted).toBe(true);
    expect(rep.content).not.toContain("eyJa.b.c");
  });
  it("throws BAD_REQUEST when full is set without private", async () => {
    const c = clientWith(new FakeBackend());
    await expect(c.getReport("camp_test", { full: true })).rejects.toBeInstanceOf(DarkmoonError);
  });
  it("returns the full report only with the two-key opt-in", async () => {
    const c = clientWith(new FakeBackend({ report: { campaignId: "camp_test", format: "markdown", content: "SECRET-BODY", ready: true } }));
    const rep = await c.getReport("camp_test", { full: true, private: true });
    expect(rep.redacted).toBe(false);
    expect(rep.content).toBe("SECRET-BODY");
  });
  it("throws ReportNotReady on a placeholder/not-ready report", async () => {
    const c = clientWith(new FakeBackend({ report: { campaignId: "camp_test", format: "markdown", content: "", ready: false } }));
    await expect(c.getReport("camp_test")).rejects.toBeInstanceOf(ReportNotReady);
  });
});

describe("evidence full opt-in", () => {
  it("requires private with full", async () => {
    const c = clientWith(new FakeBackend());
    await expect(c.listFindings({ campaignId: "camp_test" }, { includeEvidence: true, full: true })).rejects.toBeInstanceOf(DarkmoonError);
  });
});

describe("waitForCompletion hard timeout", () => {
  it("resolves when terminal", async () => {
    const be = new FakeBackend({ statuses: [campaign({ status: "running" }), campaign({ status: "completed" })] });
    const c = clientWith(be);
    const res = await c.waitForCompletion("camp_test", { pollIntervalMs: 1, timeoutMs: 5000 });
    expect(res.status).toBe("completed");
  });
  it("treats a stuck running campaign as failure (never derived from exit code)", async () => {
    const be = new FakeBackend({ statuses: [campaign({ status: "running" })] });
    const c = clientWith(be);
    await expect(c.waitForCompletion("camp_test", { pollIntervalMs: 1, timeoutMs: 30 })).rejects.toBeInstanceOf(StuckCampaignError);
  });
});
