import { NetworkError } from "../errors.js";

/**
 * Minimal Server-Sent Events reader over fetch. Yields the parsed JSON payload
 * of each `data:` frame. The Darkmoon Pro run stream emits `data: <json>\n\n`
 * frames and closes on a run_completed / run_error event (routes_run.py).
 */
export async function* readSse(
  url: string,
  opts: { token?: string | null; signal?: AbortSignal; timeoutMs?: number } = {},
): AsyncGenerator<unknown, void, unknown> {
  const headers: Record<string, string> = { Accept: "text/event-stream" };
  if (opts.token) headers["Authorization"] = `Bearer ${opts.token}`;

  let res: Response;
  try {
    res = await fetch(url, { headers, signal: opts.signal });
  } catch (err: any) {
    throw new NetworkError(`SSE connect failed: ${err?.code ?? err?.name ?? "error"}.`);
  }
  if (!res.ok || !res.body) {
    throw new NetworkError(`SSE stream returned HTTP ${res.status}.`, { status: res.status });
  }

  const reader = (res.body as any).getReader
    ? (res.body as ReadableStream<Uint8Array>).getReader()
    : null;
  const decoder = new TextDecoder();
  let buffer = "";

  const handleChunk = function* (chunk: string): Generator<unknown> {
    buffer += chunk;
    let idx: number;
    // Frames are separated by a blank line.
    while ((idx = buffer.indexOf("\n\n")) !== -1) {
      const frame = buffer.slice(0, idx);
      buffer = buffer.slice(idx + 2);
      const dataLines = frame
        .split("\n")
        .filter((l) => l.startsWith("data:"))
        .map((l) => l.slice(5).trim());
      if (dataLines.length === 0) continue;
      const payload = dataLines.join("\n");
      try {
        yield JSON.parse(payload);
      } catch {
        yield { type: "raw", data: payload };
      }
    }
  };

  if (reader) {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      yield* handleChunk(decoder.decode(value, { stream: true }));
    }
  } else {
    // Node Readable stream fallback (async iterable of Buffers).
    for await (const value of res.body as any as AsyncIterable<Uint8Array>) {
      yield* handleChunk(decoder.decode(value, { stream: true }));
    }
  }
}
