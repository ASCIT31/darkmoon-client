import { spawn } from "node:child_process";

export interface ExecResult {
  code: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

export interface ExecOptions {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  timeoutMs?: number;
  /** If set, resolve as soon as the process is spawned (detached background run). */
  detached?: boolean;
  /** Write stdout/stderr to this file when detached. */
  logFile?: string;
}

/**
 * Spawn a command WITHOUT a shell (argv array) to avoid injection. The OSS
 * backend uses this to invoke darkmoon.sh. IMPORTANT: we never derive pass/fail
 * from the exit code of a pentest run — the OSS CLI exits 0 even with criticals.
 */
export function execCommand(cmd: string, args: string[], opts: ExecOptions = {}): Promise<ExecResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      cwd: opts.cwd,
      env: opts.env ?? process.env,
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let timer: NodeJS.Timeout | undefined;

    if (opts.timeoutMs && opts.timeoutMs > 0) {
      timer = setTimeout(() => {
        timedOut = true;
        child.kill("SIGKILL");
      }, opts.timeoutMs);
    }

    child.stdout?.on("data", (d) => (stdout += d.toString()));
    child.stderr?.on("data", (d) => (stderr += d.toString()));

    child.on("error", (err) => {
      if (timer) clearTimeout(timer);
      reject(err);
    });

    child.on("close", (code, signal) => {
      if (timer) clearTimeout(timer);
      resolve({ code, signal, stdout, stderr, timedOut });
    });
  });
}

/** True if a binary/script is executable/resolvable at the given path. */
export async function which(binOrPath: string): Promise<boolean> {
  const isPath = binOrPath.includes("/");
  if (isPath) {
    try {
      const { access, constants } = await import("node:fs/promises");
      await access(binOrPath, constants.X_OK);
      return true;
    } catch {
      return false;
    }
  }
  try {
    const r = await execCommand("sh", ["-c", `command -v ${binOrPath}`], { timeoutMs: 5000 });
    return r.code === 0 && r.stdout.trim().length > 0;
  } catch {
    return false;
  }
}
