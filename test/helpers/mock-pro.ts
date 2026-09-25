import http from "node:http";
import { promises as fs } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATAROOT = path.resolve(__dirname, "../../fixtures/dataroot");

export interface MockProOptions {
  /** Return a version string from GET / (default 1.0.0). */
  version?: string;
  /** Serve GET /api/v1/system/info (default false → 404, forces root-probe). */
  systemInfo?: boolean;
  /** Require auth: reject login unless these creds match. */
  users?: Record<string, { password: string; must_change_password?: boolean }>;
  /** Force every /report to return the placeholder-200 (ReportNotReady). */
  reportPlaceholder?: boolean;
  /** Simulate a wrong service identity at GET / (edition mismatch). */
  fakeService?: string;
  /** Abruptly destroy sockets to simulate a network drop. */
  dropConnections?: boolean;
}

export interface MockProServer {
  url: string;
  close: () => Promise<void>;
  requests: string[];
}

async function readJson(p: string): Promise<any> {
  return JSON.parse(await fs.readFile(p, "utf8"));
}

async function listCampaignFiles(): Promise<string[]> {
  const files = await fs.readdir(path.join(DATAROOT, "campaigns"));
  return files.filter((f) => f.endsWith(".json"));
}

export async function startMockPro(opts: MockProOptions = {}): Promise<MockProServer> {
  const version = opts.version ?? "1.0.0";
  const requests: string[] = [];
  // In-memory stores for the Phase-2 additive endpoints.
  const webhooks: any[] = [];
  const events: any[] = [
    { event: "campaign.started", contract_version: "1", seq: 1, delivery_id: "d1", ts: "2026-09-25T10:00:00Z", data: { campaign_id: "camp_20260924_70602bf9", status: "running" } },
    { event: "finding.exploited", contract_version: "1", seq: 2, delivery_id: "d2", ts: "2026-09-25T10:01:00Z", data: { finding_id: "vuln_1", severity: "critical", status: "exploited", has_evidence: true } },
    { event: "campaign.completed", contract_version: "1", seq: 3, delivery_id: "d3", ts: "2026-09-25T10:05:00Z", data: { campaign_id: "camp_20260924_70602bf9", status: "completed" } },
  ];

  const server = http.createServer(async (req, res) => {
    requests.push(`${req.method} ${req.url}`);
    if (opts.dropConnections) {
      req.socket.destroy();
      return;
    }
    const send = (status: number, body: unknown, contentType = "application/json") => {
      res.writeHead(status, { "Content-Type": contentType });
      res.end(typeof body === "string" ? body : JSON.stringify(body));
    };
    const url = new URL(req.url ?? "/", "http://localhost");
    const p = url.pathname;

    try {
      // Root health
      if (p === "/" && req.method === "GET") {
        return send(200, { service: opts.fakeService ?? "Darkmoon Dashboard API", version, status: "running", docs: "/docs" });
      }
      if (p === "/health" && req.method === "GET") {
        return send(200, { status: "healthy", data_dir: "/data", data_dir_exists: true, projects_file_exists: true, targets_file_exists: true });
      }
      if (p === "/api/v1/system/info" && req.method === "GET") {
        if (!opts.systemInfo) return send(404, { detail: "Not Found" });
        return send(200, { edition: "pro", version });
      }

      // Auth
      if (p === "/api/v1/auth/login" && req.method === "POST") {
        const body = await readBody(req);
        if (opts.users) {
          const u = opts.users[body.username];
          if (!u || u.password !== body.password) return send(401, { detail: "Invalid credentials" });
          return send(200, {
            token: "eyJmock.jwt.token_do_not_use",
            must_change_password: Boolean(u.must_change_password),
            user: { username: body.username, role: "admin", must_change_password: Boolean(u.must_change_password) },
          });
        }
        return send(200, { token: "eyJmock.jwt.token_do_not_use", must_change_password: false, user: { username: body.username, role: "admin" } });
      }

      // Campaigns list
      if (p === "/api/v1/campaigns" && req.method === "GET") {
        const files = await listCampaignFiles();
        const data: any[] = [];
        for (const f of files) {
          const c = await readJson(path.join(DATAROOT, "campaigns", f));
          if (c.is_subagent) continue;
          if (url.searchParams.get("target_id") && c.target_id !== url.searchParams.get("target_id")) continue;
          if (url.searchParams.get("status") && c.status !== url.searchParams.get("status")) continue;
          data.push(c);
        }
        return send(200, { data, total: data.length });
      }

      // Campaign detail
      let m = p.match(/^\/api\/v1\/campaigns\/([^/]+)$/);
      if (m && req.method === "GET") {
        const id = decodeURIComponent(m[1]!);
        const file = path.join(DATAROOT, "campaigns", `${id}.json`);
        if (!(await exists(file))) return send(404, { detail: `Campaign ${id} not found` });
        const c = await readJson(file);
        const vfile = path.join(DATAROOT, "vulnerabilities", `${id}.json`);
        const vulns = (await exists(vfile)) ? await readJson(vfile) : [];
        return send(200, { data: { ...c, vulnerabilities: vulns, open_vuln: vulns.length } });
      }

      // Campaign report
      m = p.match(/^\/api\/v1\/campaigns\/([^/]+)\/report$/);
      if (m && req.method === "GET") {
        const id = decodeURIComponent(m[1]!);
        const file = path.join(DATAROOT, "campaigns", `${id}.json`);
        if (!(await exists(file))) return send(404, { detail: `Campaign ${id} not found` });
        const c = await readJson(file);
        if (opts.reportPlaceholder || !c.report_path) {
          return send(200, { campaign_id: id, format: "markdown", content: `# Report not found\n\nNo report file found for campaign ${id}.\nExpected path: ${c.report_path ?? ""}` });
        }
        const rp = path.join(DATAROOT, "reports", path.basename(c.report_path));
        if (!(await exists(rp))) {
          return send(200, { campaign_id: id, format: "markdown", content: `# Report not found\n\nNo report file found for campaign ${id}.` });
        }
        const content = await fs.readFile(rp, "utf8");
        return send(200, { campaign_id: id, format: "markdown", content });
      }

      // Vulnerabilities list
      if (p === "/api/v1/vulnerabilities" && req.method === "GET") {
        const cid = url.searchParams.get("campaign_id");
        let all: any[] = [];
        if (cid) {
          const vfile = path.join(DATAROOT, "vulnerabilities", `${cid}.json`);
          all = (await exists(vfile)) ? await readJson(vfile) : [];
        } else {
          const files = await fs.readdir(path.join(DATAROOT, "vulnerabilities"));
          for (const f of files.filter((x) => x.endsWith(".json"))) all = all.concat(await readJson(path.join(DATAROOT, "vulnerabilities", f)));
        }
        const sev = url.searchParams.get("severity");
        if (sev) all = all.filter((v) => v.severity === sev);
        return send(200, { data: all, total: all.length, stats: { by_severity: {}, by_category: {}, by_status: {} } });
      }

      // Vulnerability detail
      m = p.match(/^\/api\/v1\/vulnerabilities\/([^/]+)$/);
      if (m && req.method === "GET") {
        const id = decodeURIComponent(m[1]!);
        const files = await fs.readdir(path.join(DATAROOT, "vulnerabilities"));
        for (const f of files.filter((x) => x.endsWith(".json"))) {
          const arr = await readJson(path.join(DATAROOT, "vulnerabilities", f));
          const hit = arr.find((v: any) => String(v.id ?? v.node_id) === id);
          if (hit) return send(200, { data: hit });
        }
        return send(404, { detail: `Vulnerability ${id} not found` });
      }

      // Run launch
      if (p === "/api/v1/run/campaign" && req.method === "POST") {
        const body = await readBody(req);
        const runId = `run_20260924_120000_${Math.random().toString(16).slice(2, 10)}`;
        return send(200, { run_id: runId, pid: 4242, command: `TARGET: ${body.target}` });
      }

      // Run logs (for correlation)
      m = p.match(/^\/api\/v1\/run\/logs\/([^/]+)$/);
      if (m && req.method === "GET") {
        return send(200, { data: [{ type: "run_started", sessionID: "ses_70602bf9abcdef" }], total: 1 });
      }

      // Run stream (SSE)
      m = p.match(/^\/api\/v1\/run\/([^/]+)\/stream$/);
      if (m && req.method === "GET") {
        res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", Connection: "keep-alive" });
        res.write(`data: ${JSON.stringify({ type: "run_started", sessionID: "ses_70602bf9" })}\n\n`);
        res.write(`data: ${JSON.stringify({ type: "step", text: "scanning" })}\n\n`);
        res.write(`data: ${JSON.stringify({ type: "run_completed", campaign_id: "camp_20260924_70602bf9" })}\n\n`);
        res.end();
        return;
      }

      // Evidence metadata (must be matched before the vuln-detail $-anchored regex)
      m = p.match(/^\/api\/v1\/vulnerabilities\/([^/]+)\/evidence-meta$/);
      if (m && req.method === "GET") {
        const id = decodeURIComponent(m[1]!);
        const files = await fs.readdir(path.join(DATAROOT, "vulnerabilities"));
        for (const f of files.filter((x) => x.endsWith(".json"))) {
          const arr = await readJson(path.join(DATAROOT, "vulnerabilities", f));
          const hit = arr.find((v: any) => String(v.id ?? v.node_id) === id);
          if (hit) {
            const ev = Array.isArray(hit.evidence) ? hit.evidence : hit.evidence ? [hit.evidence] : [];
            return send(200, {
              vuln_id: id, has_evidence: ev.length > 0,
              counts: { commands: 1, payloads: 0, screenshots: 0, logs: 0, requests: 0 },
              command_names: ["curl"], has_screenshot: false, has_extracted_data: false, redacted: true,
            });
          }
        }
        return send(404, { detail: `Vulnerability ${id} not found` });
      }

      // Webhooks
      if (p === "/api/v1/webhooks" && req.method === "POST") {
        const body = await readBody(req);
        if (!body.url || !/^https?:\/\//.test(body.url)) return send(400, { detail: "webhook url must be http(s)" });
        const row = { id: `wh_${Math.random().toString(16).slice(2, 8)}`, url: body.url, events: body.events ?? [], secret: body.secret ?? "sekret_" + Math.random().toString(16).slice(2, 10), format: body.format ?? "darkmoon", enabled: true, created_at: "2026-09-25T10:00:00Z" };
        webhooks.push(row);
        return send(200, { data: row, note: "store the secret now" });
      }
      if (p === "/api/v1/webhooks" && req.method === "GET") {
        return send(200, { data: webhooks.map((w) => ({ ...w, secret: "set:" + String(w.secret).slice(-4) })), total: webhooks.length, event_types: ["finding.exploited", "campaign.completed"], contract_version: "1" });
      }
      m = p.match(/^\/api\/v1\/webhooks\/([^/]+)$/);
      if (m && req.method === "DELETE") {
        const id = decodeURIComponent(m[1]!);
        const before = webhooks.length;
        for (let i = webhooks.length - 1; i >= 0; i--) if (webhooks[i].id === id) webhooks.splice(i, 1);
        if (webhooks.length === before) return send(404, { detail: "not found" });
        return send(200, { message: "Deleted", id });
      }
      m = p.match(/^\/api\/v1\/webhooks\/([^/]+)\/test$/);
      if (m && req.method === "POST") {
        return send(200, { data: { ok: true, status: 200, attempts: 1, delivery_id: "test" } });
      }

      // Consolidated event stream (poll + SSE)
      if (p === "/api/v1/events/stream" && req.method === "GET") {
        const since = Number(url.searchParams.get("since") ?? 0);
        const wanted = (url.searchParams.get("events") ?? "").split(",").filter(Boolean);
        let batch = events.filter((e) => e.seq > since);
        if (wanted.length) batch = batch.filter((e) => wanted.includes(e.event));
        if (url.searchParams.get("poll") === "1") {
          const cursor = batch.length ? batch[batch.length - 1].seq : since;
          return send(200, { data: batch, cursor, count: batch.length, event_types: [], contract_version: "1" });
        }
        res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", Connection: "keep-alive" });
        for (const e of batch) res.write(`id: ${e.seq}\ndata: ${JSON.stringify(e)}\n\n`);
        res.end();
        return;
      }

      // Retest
      if (p === "/api/v1/retest" && req.method === "POST") {
        const body = await readBody(req);
        if (!body.target_id && !body.campaign_id) return send(400, { detail: "target_id or campaign_id is required" });
        return send(200, { retest_id: "retest_abc123", run_id: "run_retest_1", base_campaign_id: body.campaign_id ?? "camp_base", target_id: body.target_id ?? "tgt_1" });
      }
      m = p.match(/^\/api\/v1\/retest\/([^/]+)$/);
      if (m && req.method === "GET") {
        const id = decodeURIComponent(m[1]!);
        if (id === "missing") return send(404, { detail: "retest not found" });
        return send(200, {
          retest_id: id, base_campaign_id: "camp_base", new_campaign_id: "camp_new", target_id: "tgt_1", run_id: "run_retest_1",
          status: "completed",
          verdicts_summary: { fixed: 1, still_present: 1, regressed: 1, new: 1 },
          findings: [
            { finding_id: "f1", new_finding_id: null, base_status: "confirmed", new_status: null, severity: "high", verdict: "fixed" },
            { finding_id: "f2", new_finding_id: "f2b", base_status: "exploited", new_status: "exploited", severity: "critical", verdict: "still_present" },
            { finding_id: "f3", new_finding_id: "f3b", base_status: "remediated", new_status: "confirmed", severity: "medium", verdict: "regressed" },
            { finding_id: null, new_finding_id: "f4", base_status: null, new_status: "confirmed", severity: "low", verdict: "new" },
          ],
        });
      }

      // Metrics / timeseries
      if (p === "/api/v1/metrics/timeseries" && req.method === "GET") {
        const metric = url.searchParams.get("metric") ?? "severity";
        const group = url.searchParams.get("group") ?? "day";
        if (!["severity", "status", "category", "campaigns"].includes(metric)) return send(400, { detail: "bad metric" });
        return send(200, { metric, group, series: [{ key: "critical", points: [{ t: "2026-09-24", value: 2 }, { t: "2026-09-25", value: 3 }] }] });
      }

      return send(404, { detail: "Not Found" });
    } catch (err) {
      send(500, { detail: String((err as Error).message) });
    }
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  const port = typeof addr === "object" && addr ? addr.port : 0;
  return {
    url: `http://127.0.0.1:${port}`,
    requests,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

function readBody(req: http.IncomingMessage): Promise<any> {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => {
      try {
        resolve(data ? JSON.parse(data) : {});
      } catch {
        resolve({});
      }
    });
  });
}

async function exists(p: string): Promise<boolean> {
  try {
    await fs.access(p);
    return true;
  } catch {
    return false;
  }
}
