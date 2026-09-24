import { scrubSecrets } from "../redact.js";

export type LogLevel = "silent" | "error" | "warn" | "info" | "debug";

const ORDER: Record<LogLevel, number> = { silent: 0, error: 1, warn: 2, info: 3, debug: 4 };

/**
 * A logger that scrubs every message through the secret redactor before it ever
 * reaches a sink. There is no way to log an un-scrubbed string through it.
 */
export class Logger {
  constructor(
    private level: LogLevel = "warn",
    private sink: (line: string) => void = (l) => process.stderr.write(l + "\n"),
  ) {}

  setLevel(level: LogLevel): void {
    this.level = level;
  }

  private emit(level: Exclude<LogLevel, "silent">, msg: string): void {
    if (ORDER[this.level] >= ORDER[level]) {
      this.sink(`[darkmoon:${level}] ${scrubSecrets(msg)}`);
    }
  }

  error(msg: string): void {
    this.emit("error", msg);
  }
  warn(msg: string): void {
    this.emit("warn", msg);
  }
  info(msg: string): void {
    this.emit("info", msg);
  }
  debug(msg: string): void {
    this.emit("debug", msg);
  }
}
