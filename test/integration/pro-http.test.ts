import { describe, it, expect, afterEach } from "vitest";
import {
  DarkmoonClient,
  ProHttpBackend,
  AuthError,
  ReportNotReady,
  InsecureDefaultError,
  UnsupportedVersion,
  DarkmoonNotAvailable,
  NetworkError,
} from "../../src/index.js";
import { startMockPro, type MockProServer } from "../helpers/mock-pro.js";

let server: MockProServer | null = null;
afterEach(async () => {
  if (server) await server.close();
  server = null;
});

function proClient(url: string, extra: any = {}) {
  return new DarkmoonClient({ mode: "pro", pro: { baseUrl: url, ...extra } });
}

describe("ProHttpBackend (mock contract server)", () => {
  it("detects Pro via root-probe fallback when /system/info is absent", async () => {
    server = await startMockPro();
    const caps = await proClient(server.url).detect();
    expect(caps.edition).toBe("pro");
    expect(caps.detectedBy).toBe("root-probe");
    expect(caps.features.restApi).toBe(true);
  });

  it("prefers /system/info when present", async () => {
    server = await startMockPro({ systemInfo: true });
    const caps = await proClient(server.url).detect();
    expect(caps.detectedBy).toBe("system-info");
  });

  it("lists + reads campaigns and normalizes identically to OSS shapes", async () => {
    server = await startMockPro();
    const c = proClient(server.url);
    const list = await c.listCampaigns();
    expect(list.map((x) => x.id)).toContain("camp_20260924_70602bf9");
    const one = await c.getCampaign("camp_20260924_70602bf9");
    expect(one.severity.total).toBe(5);
    expect(one.edition).toBe("pro");
  });

  it("fetches findings and severity summary", async () => {
    server = await startMockPro();
    const c = proClient(server.url);
    const s = await c.getSeveritySummary("camp_20260924_70602bf9");
    expect(s.critical).toBe(2);
  });

  it("returns a redacted report by default and full only on opt-in", async () => {
    server = await startMockPro();
    const c = proClient(server.url);
    const red = await c.getReport("camp_20260924_70602bf9");
    expect(red.redacted).toBe(true);
    const full = await c.getReport("camp_20260924_70602bf9", { full: true, private: true });
    expect(full.redacted).toBe(false);
  });

  it("launch + SSE streamProgress terminates on run_completed", async () => {
    server = await startMockPro();
    const c = proClient(server.url);
    const launched = await c.launchCampaign({ target: "http://127.0.0.1:3000" });
    expect(launched.runId).toBeTruthy();
    const events: string[] = [];
    for await (const e of c.streamProgress(launched)) events.push(e.type);
    expect(events).toContain("run_completed");
    expect(events[events.length - 1]).toBe("run_completed");
  });

  // ---- Fault injection --------------------------------------------------
  it("rejects bad credentials with AuthError", async () => {
    server = await startMockPro({ users: { admin: { password: "correct" } } });
    const c = proClient(server.url, { username: "admin", password: "wrong" });
    await expect(c.launchCampaign({ target: "x" })).rejects.toBeInstanceOf(AuthError);
  });

  it("refuses when the Pro admin still has must_change_password (insecure default)", async () => {
    server = await startMockPro({ users: { admin: { password: "admin", must_change_password: true } } });
    const c = proClient(server.url, { username: "admin", password: "admin" });
    await expect(c.launchCampaign({ target: "x" })).rejects.toBeInstanceOf(InsecureDefaultError);
  });

  it("surfaces a placeholder-200 report as ReportNotReady", async () => {
    server = await startMockPro({ reportPlaceholder: true });
    const c = proClient(server.url);
    await expect(c.getReport("camp_20260924_70602bf9")).rejects.toBeInstanceOf(ReportNotReady);
  });

  it("rejects an unsupported API major during detect", async () => {
    server = await startMockPro({ version: "9.9.9" });
    await expect(proClient(server.url).detect()).rejects.toBeInstanceOf(UnsupportedVersion);
  });

  it("flags an edition mismatch (non-Darkmoon service string) as a warning", async () => {
    server = await startMockPro({ fakeService: "SomeOther API" });
    const caps = await proClient(server.url).detect();
    expect(caps.warnings.join(" ")).toMatch(/does not look like a Darkmoon/i);
  });

  it("treats an unreachable API as DarkmoonNotAvailable", async () => {
    const c = proClient("http://127.0.0.1:1"); // nothing listening
    await expect(c.detect()).rejects.toBeInstanceOf(DarkmoonNotAvailable);
  });

  it("maps a mid-stream connection drop to a NetworkError", async () => {
    server = await startMockPro({ dropConnections: true });
    const be = new ProHttpBackend({ baseUrl: server.url, timeoutMs: 2000 });
    await expect(be.listCampaigns()).rejects.toBeInstanceOf(NetworkError);
  });
});
