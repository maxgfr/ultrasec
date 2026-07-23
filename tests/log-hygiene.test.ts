import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { scanRepo } from "../src/scan.js";
import { buildGraph } from "../src/graph.js";
import { enumerateTaint } from "../src/taint.js";
import { enumerateSensitiveLogCandidates } from "../src/logs/hygiene.js";
import { findSinks, LOG_SINKS } from "../src/catalog.js";
import { langForFile } from "../src/lang.js";
import { runScan } from "../src/commands/scan.js";
import { parseArgs } from "../src/util.js";
import type { Finding } from "../src/types.js";

const FIXTURE = resolve(__dirname, "fixtures", "log-injection");

// ── Opt-in safety: the default pipeline must never see a log-hygiene finding ──
// This is the TDD anchor test — it must pass against UNMODIFIED taint code (no
// includeLogSinks option passed at all), proving `--log-hygiene` is strictly
// additive and the default sink catalog / goldens are never touched by it.
describe("log-hygiene — strictly opt-in (default pipeline unaffected)", () => {
  it("default enumerateTaint (no options) emits ZERO findings for the log-injection fixture", () => {
    const scan = scanRepo(FIXTURE);
    const graph = buildGraph(scan);
    const { findings } = enumerateTaint(scan, graph);
    expect(findings).toEqual([]);
  });

  it("default enumerateTaint with an explicit includeLogSinks: false is identical to omitting the option", () => {
    const scan = scanRepo(FIXTURE);
    const graph = buildGraph(scan);
    const a = enumerateTaint(scan, graph);
    const b = enumerateTaint(scan, graph, { includeLogSinks: false });
    expect(b.findings).toEqual(a.findings);
  });

  it("enumerateSensitiveLogCandidates is never invoked by the default (no-flag) scan pipeline: runScan without --log-hygiene yields no CWE-532/logs findings", async () => {
    const out = mkdtempSync(join(tmpdir(), "ultrasec-log-hygiene-off-"));
    const code = await runScan(parseArgs(["scan", "--repo", FIXTURE, "--out", out, "--no-enrich", "--no-tools"]));
    expect(code).toBe(0);
    const findings = JSON.parse(readFileSync(join(out, "findings.json"), "utf8")) as Finding[];
    expect(findings).toEqual([]);
  });
});

// ── CWE-117: log injection via the taint BFS, opt-in `includeLogSinks` ────────
describe("log-hygiene — CWE-117 log injection (opt-in includeLogSinks)", () => {
  it("surfaces the express req.query.q -> logger.info(q) flow as a kind:'log' finding", () => {
    const scan = scanRepo(FIXTURE);
    const graph = buildGraph(scan);
    const { findings } = enumerateTaint(scan, graph, { includeLogSinks: true });
    const hit = findings.find((f) => f.sink?.file === "src/server.js" && f.sink.kind === "log");
    expect(hit, "expected a log-kind CWE-117 finding in src/server.js").toBeTruthy();
    expect(hit!.cwe).toBe("CWE-117");
    expect(hit!.category).toBe("taint");
    expect(hit!.severity).toBe("low");
    expect(hit!.source?.kind).toBe("http");
  });

  it("surfaces the Flask request.args.get('q') -> logger.info(q) flow (Python) as a kind:'log' finding", () => {
    const scan = scanRepo(FIXTURE);
    const graph = buildGraph(scan);
    const { findings } = enumerateTaint(scan, graph, { includeLogSinks: true });
    const hit = findings.find((f) => f.sink?.file === "src/app.py" && f.sink.kind === "log");
    expect(hit, "expected a log-kind CWE-117 finding in src/app.py").toBeTruthy();
    expect(hit!.cwe).toBe("CWE-117");
  });

  it("does NOT flag the benign logger.info('server started') / 'worker ready' lines", () => {
    const scan = scanRepo(FIXTURE);
    const graph = buildGraph(scan);
    const { findings } = enumerateTaint(scan, graph, { includeLogSinks: true });
    for (const f of findings) {
      expect(f.message).not.toContain("server started");
      expect(f.message).not.toContain("worker ready");
    }
  });

  it("does NOT flag the bare log(secretToken) negative control (receiver-gating strictness)", () => {
    const scan = scanRepo(FIXTURE);
    const graph = buildGraph(scan);
    const { findings } = enumerateTaint(scan, graph, { includeLogSinks: true });
    const bareHit = findings.find((f) => f.sink?.file === "src/server.js" && f.sink.symbol === "bareLogNegativeControl");
    expect(bareHit).toBeUndefined();
  });
});

// ── Receiver-gating strictness at the catalog level ────────────────────────────
describe("LOG_SINKS — receiver-gating is hard (bare log(x) must not match)", () => {
  const lang = langForFile("x.js")!;

  it("a bare call with no receiver never matches, even to a callee/receiver name used elsewhere", () => {
    const hits = findSinks(lang, [{ callee: "log", line: 1 }], LOG_SINKS);
    expect(hits).toEqual([]);
  });

  it("the same callee WITH a recognized receiver matches", () => {
    const hits = findSinks(lang, [{ callee: "log", receiver: "console", line: 1 }], LOG_SINKS);
    expect(hits).toHaveLength(1);
    expect(hits[0]!.kind).toBe("log");
    expect(hits[0]!.cwe).toBe("CWE-117");
  });

  it("a recognized callee with an UNRECOGNIZED receiver does not match", () => {
    const hits = findSinks(lang, [{ callee: "info", receiver: "cache", line: 1 }], LOG_SINKS);
    expect(hits).toEqual([]);
  });

  it("findSinks with no extraSinks argument never returns a log-kind hit (default behaviour untouched)", () => {
    const hits = findSinks(lang, [{ callee: "log", receiver: "console", line: 1 }]);
    expect(hits.find((h) => h.kind === "log")).toBeUndefined();
  });
});

// ── CWE-532: sensitive-logging line-content pass ───────────────────────────────
describe("enumerateSensitiveLogCandidates — CWE-532 sensitive data on a log-call line", () => {
  const scan = scanRepo(FIXTURE);
  const { findings } = enumerateSensitiveLogCandidates(scan);

  it("flags the password-shaped identifier (name heuristic)", () => {
    const hit = findings.find((f) => f.sink?.file === "src/server.js" && f.sink?.symbol === "logLogin");
    expect(hit, "expected a CWE-532 finding on logLogin's log line").toBeTruthy();
    expect(hit!.cwe).toBe("CWE-532");
    expect(hit!.category).toBe("logs");
    expect(hit!.severity).toBe("medium");
    expect(hit!.confidence).toBe("low");
  });

  it("flags the literal AWS access key (SECRET_PATTERNS)", () => {
    const hit = findings.find((f) => f.sink?.file === "src/server.js" && f.sink?.symbol === "logStartupKey");
    expect(hit, "expected a CWE-532 finding on logStartupKey's log line").toBeTruthy();
    expect(hit!.cwe).toBe("CWE-532");
  });

  it("does NOT flag the benign logBoot/log_boot lines", () => {
    const boot = findings.find((f) => f.sink?.symbol === "logBoot" || f.sink?.symbol === "log_boot");
    expect(boot).toBeUndefined();
  });

  it("does NOT flag the bare log(secretToken) negative control (never reaches the sink-matching step)", () => {
    const bareHit = findings.find((f) => f.sink?.symbol === "bareLogNegativeControl");
    expect(bareHit).toBeUndefined();
  });

  it("redacts the message: the raw AWS key literal never appears anywhere in the finding set", () => {
    const blob = JSON.stringify(findings);
    expect(blob).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(blob).toContain("REDACTED");
  });

  it("caps the embedded redacted line in the message at 200 chars (EVIDENCE_MAX, shared with analyze.ts)", () => {
    const dir = mkdtempSync(join(tmpdir(), "ultrasec-log-hygiene-long-line-"));
    const longValue = "x".repeat(400);
    writeFileSync(
      join(dir, "long.js"),
      `function logLongPassword() {\n  logger.info("password=" + "${longValue}");\n}\nmodule.exports = { logLongPassword };\n`,
    );
    const scan = scanRepo(dir);
    const { findings: longFindings } = enumerateSensitiveLogCandidates(scan);
    const hit = longFindings.find((f) => f.sink?.symbol === "logLongPassword");
    expect(hit, "expected a CWE-532 finding on the long password line").toBeTruthy();
    // The embedded backtick-quoted evidence segment must never exceed 200 chars.
    const evidence = hit!.message.match(/: `(.*)`\. /)?.[1];
    expect(evidence, "expected a backtick-quoted evidence segment in the message").toBeTruthy();
    expect(evidence!.length).toBeLessThanOrEqual(200);
    // Sanity: the untruncated line would have been well over 200 chars.
    expect(longValue.length).toBeGreaterThan(200);
  });

  it("rank-then-caps and reports truncation (never silent)", () => {
    const capped = enumerateSensitiveLogCandidates(scan, { maxCandidates: 1 });
    expect(capped.findings).toHaveLength(1);
    expect(capped.total).toBe(findings.length);
    expect(capped.truncated).toBe(findings.length - 1);
  });

  it("is idempotent (stable ids across repeated calls)", () => {
    const again = enumerateSensitiveLogCandidates(scan).findings;
    expect(again.map((f) => f.id)).toEqual(findings.map((f) => f.id));
  });
});

// ── Default cap of 40 actually engages on a large corpus ───────────────────────
describe("enumerateSensitiveLogCandidates — default cap (40) engages under real load", () => {
  const N = 45;
  function synthesizeCorpus(): string {
    const dir = mkdtempSync(join(tmpdir(), "ultrasec-log-hygiene-cap-"));
    for (let i = 0; i < N; i++) {
      writeFileSync(join(dir, `f${i}.js`), `function f${i}() {\n  const token = "t${i}";\n  logger.info("token=" + token);\n}\nmodule.exports = { f${i} };\n`);
    }
    return dir;
  }

  it("synthesizes 45 sensitive-log hits and confirms the default cap keeps exactly 40, reporting the rest as truncated", () => {
    const scan = scanRepo(synthesizeCorpus());
    const { findings, truncated, total } = enumerateSensitiveLogCandidates(scan);
    expect(total).toBe(N);
    expect(findings).toHaveLength(40);
    expect(truncated).toBe(N - 40);
  });

  it("a raised `maxCandidates` option lets all 45 through with zero truncation", () => {
    const scan = scanRepo(synthesizeCorpus());
    const { findings, truncated, total } = enumerateSensitiveLogCandidates(scan, { maxCandidates: 5000 });
    expect(total).toBe(N);
    expect(findings).toHaveLength(N);
    expect(truncated).toBe(0);
  });

  // ── CLI wiring regression: `scan --log-hygiene` must forward `--max-candidates`
  // to the hygiene pass exactly as it does for taint/--sinks, so the truncation
  // advisory ("Raise --max-candidates") is genuinely actionable for this pass too.
  it("`scan --log-hygiene --max-candidates 5000` raises the hygiene cap end-to-end (all 45, truncated: 0)", async () => {
    const dir = synthesizeCorpus();
    const out = mkdtempSync(join(tmpdir(), "ultrasec-log-hygiene-cap-cli-high-"));
    const code = await runScan(parseArgs(["scan", "--repo", dir, "--out", out, "--no-enrich", "--no-tools", "--log-hygiene", "--max-candidates", "5000"]));
    expect(code).toBe(0);
    const findings = JSON.parse(readFileSync(join(out, "findings.json"), "utf8")) as Finding[];
    const manifest = JSON.parse(readFileSync(join(out, "manifest.json"), "utf8"));
    const cwe532 = findings.filter((f) => f.cwe === "CWE-532");
    expect(cwe532).toHaveLength(N);
    expect(manifest.truncation).toBeUndefined();
  });

  it("`scan --log-hygiene` without --max-candidates keeps today's behavior unchanged (40 kept, 5 truncated)", async () => {
    const dir = synthesizeCorpus();
    const out = mkdtempSync(join(tmpdir(), "ultrasec-log-hygiene-cap-cli-default-"));
    const code = await runScan(parseArgs(["scan", "--repo", dir, "--out", out, "--no-enrich", "--no-tools", "--log-hygiene"]));
    expect(code).toBe(0);
    const findings = JSON.parse(readFileSync(join(out, "findings.json"), "utf8")) as Finding[];
    const manifest = JSON.parse(readFileSync(join(out, "manifest.json"), "utf8"));
    const cwe532 = findings.filter((f) => f.cwe === "CWE-532");
    expect(cwe532).toHaveLength(40);
    expect(manifest.truncation?.candidates).toBe(N - 40);
  });
});

// ── End-to-end via `scan --log-hygiene` ─────────────────────────────────────────
describe("scan --log-hygiene — CLI wiring", () => {
  it("merges CWE-117 (kind:'log') and CWE-532 findings into the dossier, counted in the manifest", async () => {
    const out = mkdtempSync(join(tmpdir(), "ultrasec-log-hygiene-on-"));
    const code = await runScan(parseArgs(["scan", "--repo", FIXTURE, "--out", out, "--no-enrich", "--no-tools", "--log-hygiene"]));
    expect(code).toBe(0);

    const findings = JSON.parse(readFileSync(join(out, "findings.json"), "utf8")) as Finding[];
    const manifest = JSON.parse(readFileSync(join(out, "manifest.json"), "utf8"));

    const cwe117 = findings.filter((f) => f.cwe === "CWE-117" && f.sink?.kind === "log");
    const cwe532 = findings.filter((f) => f.cwe === "CWE-532");
    expect(cwe117.length).toBeGreaterThan(0);
    expect(cwe532.length).toBeGreaterThan(0);
    expect(manifest.counts.findings).toBe(findings.length);

    // Redaction guarantee holds through the full dossier round-trip too.
    const blob = JSON.stringify(findings);
    expect(blob).not.toContain("AKIAIOSFODNN7EXAMPLE");
  });

  it("without --log-hygiene, the same fixture still yields zero findings via the CLI (belt-and-braces on the opt-in guarantee)", async () => {
    const out = mkdtempSync(join(tmpdir(), "ultrasec-log-hygiene-off2-"));
    const code = await runScan(parseArgs(["scan", "--repo", FIXTURE, "--out", out, "--no-enrich", "--no-tools"]));
    expect(code).toBe(0);
    const findings = JSON.parse(readFileSync(join(out, "findings.json"), "utf8")) as Finding[];
    expect(findings).toEqual([]);
  });
});
