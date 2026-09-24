import { NetworkError, AuthError, DarkmoonError } from "../errors.js";

export interface HttpOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: unknown;
  timeoutMs?: number;
  /** Bearer token; sent as Authorization header, never logged. */
  token?: string | null;
  /** Accept a non-2xx status without throwing (caller inspects .status). */
  allowStatuses?: number[];
}

export interface HttpResponse<T = unknown> {
  status: number;
  ok: boolean;
  data: T;
  text: string;
  headers: Headers;
}

/**
 * fetch wrapper with a hard timeout, JSON handling, and typed network/auth
 * errors. NEVER logs headers or bodies (they may carry the JWT / secrets).
 */
export async function httpRequest<T = unknown>(url: string, opts: HttpOptions = {}): Promise<HttpResponse<T>> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), opts.timeoutMs ?? 15_000);
  const headers: Record<string, string> = { Accept: "application/json", ...opts.headers };
  let body: string | undefined;
  if (opts.body !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(opts.body);
  }
  if (opts.token) headers["Authorization"] = `Bearer ${opts.token}`;

  let res: Response;
  try {
    res = await fetch(url, { method: opts.method ?? "GET", headers, body, signal: controller.signal });
  } catch (err: any) {
    if (err?.name === "AbortError") {
      throw new NetworkError(`Request timed out after ${opts.timeoutMs ?? 15_000}ms.`, { url: safeUrl(url) });
    }
    throw new NetworkError(`Could not reach ${safeUrl(url)}: ${err?.code ?? err?.name ?? "connection failed"}.`, { url: safeUrl(url) });
  } finally {
    clearTimeout(timeout);
  }

  const text = await res.text();
  let data: unknown = undefined;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = undefined;
    }
  }

  if (res.status === 401 || res.status === 403) {
    if (!opts.allowStatuses?.includes(res.status)) {
      throw new AuthError(`Unauthorized (HTTP ${res.status}).`, { url: safeUrl(url) });
    }
  }
  if (!res.ok && !opts.allowStatuses?.includes(res.status)) {
    throw new DarkmoonError("NETWORK", `HTTP ${res.status} from ${safeUrl(url)}.`, { status: res.status });
  }

  return { status: res.status, ok: res.ok, data: data as T, text, headers: res.headers };
}

/** Strip query/userinfo from a URL for safe logging. */
export function safeUrl(url: string): string {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}${u.pathname}`;
  } catch {
    return url.split("?")[0] ?? url;
  }
}
