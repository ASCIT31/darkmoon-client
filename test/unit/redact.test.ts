import { describe, it, expect } from "vitest";
import { scrubSecrets, scrubDeep, redactReport, looksLikeSecret } from "../../src/index.js";

describe("scrubSecrets", () => {
  it("masks JWTs", () => {
    const s = "token=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIn0.abcdefghijklmnop";
    const out = scrubSecrets(s);
    expect(out).not.toContain("eyJ0eXAi");
    expect(out).toContain("REDACTED");
  });
  it("masks provider API keys, PATs and license keys", () => {
    expect(scrubSecrets("sk-ant-api03-ABCDEFGHIJKLMNOP1234")).toContain("REDACTED:API_KEY");
    expect(scrubSecrets("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")).toContain("REDACTED:GITHUB_PAT");
    expect(scrubSecrets("KEY: ABCDE-FGHIJ-KLMNO-PQRST")).toContain("REDACTED:LICENSE_KEY");
  });
  it("masks credential key=value pairs while keeping the key name", () => {
    const out = scrubSecrets("password=Sup3rSecretValue");
    expect(out).toMatch(/password=«REDACTED/);
  });
  it("leaves benign text untouched", () => {
    expect(scrubSecrets("SQL injection on /rest/user/login")).toBe("SQL injection on /rest/user/login");
  });
});

describe("scrubDeep", () => {
  it("recursively scrubs strings in objects/arrays", () => {
    const out = scrubDeep({ a: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345", b: [{ c: "ok" }] }) as any;
    expect(out.a).toContain("REDACTED");
    expect(out.b[0].c).toBe("ok");
  });
});

describe("redactReport", () => {
  it("blanks fenced code blocks (evidence) but keeps prose", () => {
    const md = "## Finding\nprose here\n\n```http\nAuthorization: Bearer eyJreal.jwt.here\n```\n";
    const out = redactReport(md);
    expect(out).toContain("## Finding");
    expect(out).toContain("prose here");
    expect(out).toContain("evidence redacted");
    expect(out).not.toContain("eyJreal.jwt.here");
  });
});

describe("looksLikeSecret", () => {
  it("detects secret material", () => {
    expect(looksLikeSecret("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")).toBe(true);
    expect(looksLikeSecret("nothing here")).toBe(false);
  });
});
