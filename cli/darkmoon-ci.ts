/**
 * darkmoon-ci — portable CI CLI built on @darkmoon/client.
 *
 * Jenkins / GitLab / any runner call this bin. It launches, waits, fetches
 * findings/summary/report, and emits a fail-policy exit code computed FROM
 * FINDINGS (never from the pentest process exit code). Strict secret hygiene:
 * the redaction-safe surface by default; the full report needs an explicit
 * two-key opt-in.
 *
 * Exit codes: 0 = pass, 2 = fail-policy tripped, 1 = tool/usage/runtime error.
 */
import { parseArgs } from "node:util";
import { promises as fs } from "node:fs";
import {
  DarkmoonClient,
  type DarkmoonClientConfig,
  type ClientMode,
  computeFailPolicy,
  parseFailOn,
  scrubSecrets,
  DarkmoonError,
  CONTRACT_VERSION,
  type Finding,
  type LaunchInput,
} from "../src/index.js";

const EXIT_OK = 0;
const EXIT_ERROR = 1;
const EXIT_POLICY = 2;

function env(name: string): string | undefined {
  const v = process.env[name];
  return v && v.length ? v : undefined;
}

function buildConfig(opts: Record<string, unknown>): DarkmoonClientConfig {
  const mode = ((opts.mode as string) ?? env("DARKMOON_MODE") ?? "auto") as ClientMode;
  const proUrl = (opts["pro-url"] as string) ?? env("DARKMOON_PRO_URL");
  const ossData = (opts["oss-data-dir"] as string) ?? env("DARKMOON_OSS_DATA_DIR");
  const cfg: DarkmoonClientConfig = { mode, logLevel: (opts.verbose ? "debug" : "warn") as any };
  if (proUrl) {
    cfg.pro = {
      baseUrl: proUrl,
      username: (opts["pro-user"] as string) ?? env("DARKMOON_PRO_USER"),
      password: (opts["pro-pass"] as string) ?? env("DARKMOON_PRO_PASS"),
      token: (opts["pro-token"] as string) ?? env("DARKMOON_PRO_TOKEN"),
      refuseInsecureDefault: opts["allow-insecure-default"] ? false : true,
      timeoutMs: opts.timeout ? Number(opts.timeout) * 1000 : undefined,
    };
  }
  if (ossData) {
    cfg.oss = {
      dataDir: ossData,
      reportsDir: (opts["oss-reports-dir"] as string) ?? env("DARKMOON_OSS_REPORTS_DIR"),
      scriptPath: (opts["oss-script"] as string) ?? env("DARKMOON_OSS_SCRIPT"),
    };
  }
  return cfg;
}

function out(json: boolean, human: string, obj: unknown): void {
  if (json) process.stdout.write(JSON.stringify(obj, null, 2) + "\n");
  else process.stdout.write(human + "\n");
}

function launchInputFrom(opts: Record<string, unknown>): LaunchInput {
  const csv = (v: unknown): string[] | undefined => (typeof v === "string" && v.length ? v.split(",").map((s) => s.trim()) : undefined);
  return {
    target: String(opts.target),
    program: opts.program as string | undefined,
    focus: csv(opts.focus),
    severity: opts.severity as string | undefined,
    outOfScope: csv(opts["out-of-scope"]),
    exclude: csv(opts.exclude),
  };
}

const HELP = `darkmoon-ci — Darkmoon CI client (contract v${CONTRACT_VERSION})

Usage: darkmoon-ci <command> [options]

Commands:
  detect                         Print the detected backend + capabilities
  launch  --target <t>           Launch a campaign; prints a correlation handle
  status  <campaignId>           Print a campaign's normalized status
  summary <campaignId>           Print the severity summary
  findings <campaignId>          List findings (redaction-safe)
  report  <campaignId>           Fetch the report (redacted unless --full --private)
  wait    <campaignId>           Poll until terminal; apply --fail-on exit code
  run     --target <t>           launch + wait + summary + fail-policy (CI one-shot)

Backend options:
  --mode auto|oss|pro            (env DARKMOON_MODE)
  --pro-url <url>                (env DARKMOON_PRO_URL)
  --pro-user / --pro-pass        (env DARKMOON_PRO_USER / DARKMOON_PRO_PASS)
  --pro-token <jwt>              (env DARKMOON_PRO_TOKEN)
  --oss-data-dir <dir>          (env DARKMOON_OSS_DATA_DIR)
  --oss-reports-dir <dir>       (env DARKMOON_OSS_REPORTS_DIR)
  --oss-script <path>           (env DARKMOON_OSS_SCRIPT)

Common options:
  --json                         Machine-readable output
  --fail-on critical,high        Severities that fail the build (default critical,high)
  --timeout <seconds>            Hard timeout for wait/run (default 3600)
  --poll <seconds>               Poll interval (default 5)
  --full --private               (report) emit the UN-redacted report — internal only
  --out <file>                   (report) write to a file instead of stdout
  --allow-insecure-default       Do not refuse when Pro admin has default password
  --verbose                      Debug logging (still secret-scrubbed)
  -h, --help                     This help

Exit codes: 0 pass · 2 fail-policy tripped · 1 tool/usage error
`;

async function main(argv: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      mode: { type: "string" },
      "pro-url": { type: "string" },
      "pro-user": { type: "string" },
      "pro-pass": { type: "string" },
      "pro-token": { type: "string" },
      "oss-data-dir": { type: "string" },
      "oss-reports-dir": { type: "string" },
      "oss-script": { type: "string" },
      target: { type: "string" },
      program: { type: "string" },
      focus: { type: "string" },
      severity: { type: "string" },
      "out-of-scope": { type: "string" },
      exclude: { type: "string" },
      "fail-on": { type: "string" },
      timeout: { type: "string" },
      poll: { type: "string" },
      json: { type: "boolean", default: false },
      full: { type: "boolean", default: false },
      private: { type: "boolean", default: false },
      out: { type: "string" },
      "allow-insecure-default": { type: "boolean", default: false },
      verbose: { type: "boolean", default: false },
      help: { type: "boolean", short: "h", default: false },
    },
  });

  const cmd = positionals[0];
  const json = Boolean(values.json);
  if (values.help || !cmd) {
    process.stdout.write(HELP);
    return values.help ? EXIT_OK : EXIT_ERROR;
  }

  const client = new DarkmoonClient(buildConfig(values));
  const ref = positionals[1];
  const timeoutMs = values.timeout ? Number(values.timeout) * 1000 : undefined;
  const pollIntervalMs = values.poll ? Number(values.poll) * 1000 : undefined;

  switch (cmd) {
    case "detect": {
      const caps = await client.detect();
      out(json, `edition=${caps.edition} version=${caps.version} available=${caps.available}\n` +
        `features: ${Object.entries(caps.features).filter(([, v]) => v).map(([k]) => k).join(", ") || "none"}` +
        (caps.warnings.length ? `\nwarnings:\n - ${caps.warnings.map(scrubSecrets).join("\n - ")}` : ""), caps);
      return EXIT_OK;
    }
    case "launch": {
      if (!values.target) throw usage("launch requires --target");
      const res = await client.launchCampaign(launchInputFrom(values));
      out(json, `launched: runId=${res.runId ?? "-"} nonce=${res.correlation.nonce ?? "-"} (correlation deferred)`, res);
      return EXIT_OK;
    }
    case "status": {
      if (!ref) throw usage("status requires a <campaignId>");
      const c = await client.getCampaignStatus(ref);
      out(json, `campaign ${c.id}: status=${c.status} risk=${c.overallRisk} findings=${c.severity.total}`, stripRaw(c));
      return EXIT_OK;
    }
    case "summary": {
      if (!ref) throw usage("summary requires a <campaignId>");
      const s = await client.getSeveritySummary(ref);
      out(json, `critical=${s.critical} high=${s.high} medium=${s.medium} low=${s.low} info=${s.info} total=${s.total}`, s);
      return EXIT_OK;
    }
    case "findings": {
      if (!ref) throw usage("findings requires a <campaignId>");
      const findings = await client.listFindings({ campaignId: ref, severity: values.severity });
      out(
        json,
        findings.map((f) => `[${f.severity}] ${f.title ?? f.id} (${f.status})`).join("\n") || "(no findings)",
        findings.map(stripRaw),
      );
      return EXIT_OK;
    }
    case "report": {
      if (!ref) throw usage("report requires a <campaignId>");
      const rep = await client.getReport(ref, { full: Boolean(values.full), private: Boolean(values.private) });
      if (values.out) {
        await fs.writeFile(String(values.out), rep.content, "utf8");
        out(json, `report written to ${values.out} (redacted=${rep.redacted})`, { file: values.out, redacted: rep.redacted });
      } else {
        out(json, rep.content, rep);
      }
      return EXIT_OK;
    }
    case "wait": {
      if (!ref) throw usage("wait requires a <campaignId>");
      const c = await client.waitForCompletion(ref, { timeoutMs, pollIntervalMs, onProgress: (p) => values.verbose && process.stderr.write(`[status] ${p.status}\n`) });
      const findings = await client.listFindings({ campaignId: c.id });
      return emitVerdict(c.severity.total ? findings : [], values, json, c.id);
    }
    case "run": {
      if (!values.target) throw usage("run requires --target");
      const launched = await client.launchCampaign(launchInputFrom(values));
      process.stderr.write(`[darkmoon-ci] launched (nonce=${launched.correlation.nonce}); waiting...\n`);
      const c = await client.waitForCompletion(launched, { timeoutMs, pollIntervalMs, onProgress: (p) => process.stderr.write(`[status] ${p.status}\n`) });
      const findings = await client.listFindings({ campaignId: c.id });
      return emitVerdict(findings, values, json, c.id);
    }
    default:
      process.stderr.write(`Unknown command: ${cmd}\n\n${HELP}`);
      return EXIT_ERROR;
  }
}

function emitVerdict(findings: Finding[], values: Record<string, unknown>, json: boolean, campaignId: string): number {
  const verdict = computeFailPolicy(findings, parseFailOn(values["fail-on"] as string));
  const payload = {
    campaignId,
    verdict: verdict.failed ? "fail" : "pass",
    failOn: verdict.failOn,
    offending: verdict.offending,
    total: findings.length,
    reason: verdict.reason,
  };
  out(json, `${verdict.failed ? "FAIL" : "PASS"} — ${verdict.reason}`, payload);
  return verdict.failed ? EXIT_POLICY : EXIT_OK;
}

function stripRaw<T extends { raw?: unknown }>(o: T): Omit<T, "raw"> {
  const { raw: _raw, ...rest } = o;
  return rest;
}

function usage(msg: string): DarkmoonError {
  return new DarkmoonError("BAD_REQUEST", msg);
}

main(process.argv.slice(2))
  .then((code) => process.exit(code))
  .catch((err) => {
    const msg = err instanceof DarkmoonError ? `${err.code}: ${err.message}` : String(err?.message ?? err);
    process.stderr.write(`[darkmoon-ci] error: ${scrubSecrets(msg)}\n`);
    process.exit(EXIT_ERROR);
  });
