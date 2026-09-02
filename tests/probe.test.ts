import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createServer, type Server } from "node:http";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runProbe } from "../src/commands/probe.js";
import { runCheck } from "../src/commands/check.js";
import { writeDossier, type Dossier } from "../src/store.js";
import { parseArgs } from "../src/util.js";
import type { Finding, Status } from "../src/types.js";

// WS5 — the isolated live-site probe. Tested against a LOCAL http server on
// 127.0.0.1 (loopback → exercises the --allow-private rail). The load-bearing
// property under test is ISOLATION: probe output goes to PROBE.json only, never
// findings.json, so the `check` gate is untouched.

let server: Server;
let base: string;

beforeAll(async () => {
  server = createServer((req, res) => {
    if (req.method === "OPTIONS") {
      // Reflect the caller's Origin — the CORS-reflection posture bug.
      res.setHeader("Access-Control-Allow-Origin", req.headers.origin ?? "*");
      res.setHeader("Access-Control-Allow-Credentials", "true");
      res.writeHead(204);
      res.end();
      return;
    }
    if (req.url?.startsWith("/.well-known/security.txt")) {
      res.writeHead(404);
      res.end("not found");
      return;
    }
    // A deliberately insecure response: no security headers, a flagless cookie,
    // a version-bearing Server banner.
    res.setHeader("Set-Cookie", "sid=abc123; Path=/");
    res.setHeader("Server", "nginx/1.18.0");
    res.writeHead(200, { "content-type": "text/html" });
    res.end("<html>ok</html>");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const addr = server.address();
  const port = typeof addr === "object" && addr ? addr.port : 0;
  base = `http://127.0.0.1:${port}`;
});

afterAll(() => new Promise<void>((r) => server.close(() => r())));

const silence = () => {
  const o = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
  const e = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  return () => {
    o.mockRestore();
    e.mockRestore();
  };
};

const readReport = (out: string) =>
  JSON.parse(readFileSync(join(out, "PROBE.json"), "utf8")) as { findings: { area: string; title: string; grounding: string }[] };

describe("probe — safety rails", () => {
  it("refuses without --i-own-this (exit 2)", async () => {
    const restore = silence();
    expect(await runProbe(parseArgs(["probe", base, "--allow-private"]))).toBe(2);
    restore();
  });

  it("refuses a private/loopback target without --allow-private (exit 2)", async () => {
    const restore = silence();
    expect(await runProbe(parseArgs(["probe", base, "--i-own-this"]))).toBe(2);
    restore();
  });

  it("rejects a non-http(s) scheme (exit 2)", async () => {
    const restore = silence();
    expect(await runProbe(parseArgs(["probe", "ftp://127.0.0.1", "--i-own-this", "--allow-private"]))).toBe(2);
    restore();
  });
});

describe("probe — posture checks over the wire", () => {
  it("writes PROBE.json (never findings.json) and detects header/cookie/transport/cors issues", async () => {
    const out = mkdtempSync(join(tmpdir(), "ultrasec-probe-"));
    const restore = silence();
    const code = await runProbe(parseArgs(["probe", base, "--i-own-this", "--allow-private", "--out", out]));
    restore();
    expect(code).toBe(0);

    // Isolation: the probe wrote its OWN artifact and never the static dossier.
    expect(existsSync(join(out, "PROBE.json"))).toBe(true);
    expect(existsSync(join(out, "PROBE.md"))).toBe(true);
    expect(existsSync(join(out, "findings.json"))).toBe(false);

    const areas = new Set(readReport(out).findings.map((f) => f.area));
    expect(areas.has("headers")).toBe(true); // missing CSP/HSTS/XFO…
    expect(areas.has("cookie")).toBe(true); // flagless sid cookie
    expect(areas.has("transport")).toBe(true); // cleartext HTTP
    expect(areas.has("cors")).toBe(true); // reflected Origin
  });

  it("grounds every finding on a wire citation, never a [file:line]", async () => {
    const out = mkdtempSync(join(tmpdir(), "ultrasec-probe-"));
    const restore = silence();
    await runProbe(parseArgs(["probe", base, "--i-own-this", "--allow-private", "--out", out]));
    restore();
    for (const f of readReport(out).findings) {
      expect(f.grounding).toMatch(/^\[(response-header|cookie|tls|url):?/);
    }
  });
});

describe("probe — DNS pinning (no second resolution between the check and the socket)", () => {
  it("connects to the address the private-range check approved, not to what DNS says at connect time", async () => {
    // `.invalid` is reserved (RFC 2606) and never resolves. If the socket did
    // its own lookup the request would fail; the pinned address from the check
    // is the only way to reach the fixture server.
    const port = new URL(base).port;
    const target = `http://does-not-resolve.invalid:${port}`;
    const out = mkdtempSync(join(tmpdir(), "ultrasec-probe-pin-"));
    const resolveIp = vi.fn(async () => ({ address: "127.0.0.1", family: 4 as const }));
    const restore = silence();
    const code = await runProbe(parseArgs(["probe", target, "--i-own-this", "--allow-private", "--out", out]), { resolveIp });
    restore();
    expect(code).toBe(0);
    expect(resolveIp).toHaveBeenCalledTimes(1); // one lookup per run — the check's
    const report = JSON.parse(readFileSync(join(out, "PROBE.json"), "utf8")) as { resolvedIp: string; observed: { status: number }; requestsMade: number };
    expect(report.resolvedIp).toBe("127.0.0.1");
    expect(report.observed.status).toBe(200);
    expect(report.requestsMade).toBeGreaterThan(1); // every follow-up request was pinned too
  });

  it("still refuses a pinned private address without --allow-private", async () => {
    const resolveIp = async () => ({ address: "169.254.169.254", family: 4 as const });
    const restore = silence();
    const code = await runProbe(parseArgs(["probe", "http://metadata.example.test", "--i-own-this"]), { resolveIp });
    restore();
    expect(code).toBe(2);
  });
});

describe("probe — does not contaminate the check gate", () => {
  const REPO = join(import.meta.dirname, "fixtures", "vuln-express");

  const seededRun = (): string => {
    const run = mkdtempSync(join(tmpdir(), "ultrasec-probe-check-"));
    const finding: Finding = {
      id: "f1",
      category: "taint",
      cwe: "CWE-89",
      title: "SQLi",
      severity: "high",
      confidence: "high",
      message: "m",
      tool: "ultrasec",
      status: "confirmed" as Status,
      sink: { file: "src/db.js", line: 6 },
    };
    const d: Dossier = {
      manifest: {
        version: "0",
        schemaVersion: 7,
        repo: REPO,
        generatedNote: "",
        languages: ["javascript"],
        toolsRun: [],
        counts: { findings: 1, bySeverity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 } },
      },
      findings: [finding],
      graph: { files: [], edges: [], symbolDefs: {} },
    };
    writeDossier(run, d);
    return run;
  };

  it("check stays green after a probe writes into the same run dir", async () => {
    const run = seededRun();
    const restore = silence();
    await runProbe(parseArgs(["probe", base, "--i-own-this", "--allow-private", "--out", run]));
    const code = runCheck(parseArgs(["check", "--run", run, "--repo", REPO, "--semantic"]));
    restore();
    expect(existsSync(join(run, "PROBE.json"))).toBe(true);
    expect(code).toBe(0); // probe's [url]/[response-header] findings are invisible to check
  });
});
