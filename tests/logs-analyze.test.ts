import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { analyzeLogs } from "../src/logs/analyze.js";
import { SEVERITIES } from "../src/types.js";

const FIXTURES = join(import.meta.dirname, "fixtures", "logs");
const NGINX = join(FIXTURES, "nginx-combined.log");
const JSONL = join(FIXTURES, "app.jsonl");

const nginxRaw = readFileSync(NGINX, "utf8").split("\n");
// 1-based line number of the first raw line containing `needle`.
function lineOf(needle: string): number {
  const i = nginxRaw.findIndex((l) => l.includes(needle));
  if (i < 0) throw new Error(`fixture line containing ${JSON.stringify(needle)} not found`);
  return i + 1;
}

function severityRank(s: string): number {
  return SEVERITIES.indexOf(s as (typeof SEVERITIES)[number]);
}

describe("analyzeLogs — signature true positives", () => {
  it("finds the planted sqlmap scanner UA", async () => {
    const { findings } = await analyzeLogs([NGINX], { budget: "standard", redact: true, base: FIXTURES });
    const line = lineOf("sqlmap/1.7.2");
    const hit = findings.find((f) => f.sink?.file === "nginx-combined.log" && f.sink.line === line);
    expect(hit).toBeDefined();
    expect(hit!.sink!.kind).toBe("scanner-ua");
    expect(hit!.message).toContain("sqlmap");
  });

  it("finds the planted UNION SELECT sqli attempt", async () => {
    const { findings } = await analyzeLogs([NGINX], { budget: "standard", redact: true, base: FIXTURES });
    const line = lineOf("UNION%20SELECT");
    const hit = findings.find((f) => f.sink?.file === "nginx-combined.log" && f.sink.line === line && f.sink.kind === "sqli");
    expect(hit).toBeDefined();
    expect(hit!.cwe).toBe("CWE-89");
    expect(hit!.severity).toBe("high");
  });

  it("finds the ../../etc/passwd traversal attempt (404, not escalated)", async () => {
    const { findings } = await analyzeLogs([NGINX], { budget: "standard", redact: true, base: FIXTURES });
    const line = lineOf("/../../etc/passwd");
    const hits = findings.filter((f) => f.sink?.file === "nginx-combined.log" && f.sink.line === line && f.sink.kind === "traversal");
    expect(hits.length).toBeGreaterThan(0);
    expect(hits.every((f) => f.cwe === "CWE-22")).toBe(true);
    expect(hits.every((f) => !f.message.includes("succeeded"))).toBe(true);
  });

  it("finds the .aws/credentials probe-path hit", async () => {
    const { findings } = await analyzeLogs([NGINX], { budget: "standard", redact: true, base: FIXTURES });
    const line = lineOf(".aws/credentials");
    const hit = findings.find((f) => f.sink?.file === "nginx-combined.log" && f.sink.line === line && f.sink.kind === "probe-path");
    expect(hit).toBeDefined();
  });

  it("finds /actuator/env as a probe-path hit, escalated (200)", async () => {
    const { findings } = await analyzeLogs([NGINX], { budget: "standard", redact: true, base: FIXTURES });
    const line = lineOf("/actuator/env");
    const hit = findings.find((f) => f.sink?.file === "nginx-combined.log" && f.sink.line === line && f.sink.kind === "probe-path");
    expect(hit).toBeDefined();
    expect(hit!.message).toContain("succeeded — 2xx");
  });
});

describe("analyzeLogs — false-positive resistance (benign twins)", () => {
  it("does not flag '?q=selection' as sqli (word-boundary safe)", async () => {
    const { findings } = await analyzeLogs([NGINX], { budget: "standard", redact: true, base: FIXTURES });
    const line = lineOf("q=selection");
    const hits = findings.filter((f) => f.sink?.file === "nginx-combined.log" && f.sink.line === line);
    expect(hits).toHaveLength(0);
  });

  it("does not flag /blog/wp-login-guide as a probe-path hit", async () => {
    const { findings } = await analyzeLogs([NGINX], { budget: "standard", redact: true, base: FIXTURES });
    const line = lineOf("wp-login-guide");
    const hits = findings.filter((f) => f.sink?.file === "nginx-combined.log" && f.sink.line === line);
    expect(hits).toHaveLength(0);
  });

  it("does not flag /blog/actuator-tips as a probe-path hit (no slash after 'actuator')", async () => {
    const { findings } = await analyzeLogs([NGINX], { budget: "standard", redact: true, base: FIXTURES });
    const line = lineOf("actuator-tips");
    const hits = findings.filter((f) => f.sink?.file === "nginx-combined.log" && f.sink.line === line);
    expect(hits).toHaveLength(0);
  });

  it("does not flag 'union membership selection committee' as sqli (harder adversarial input: contains 'union' and 'select' as a substring of 'selection', not the whole word)", async () => {
    const { findings } = await analyzeLogs([NGINX], { budget: "standard", redact: true, base: FIXTURES });
    const line = lineOf("union%20membership%20selection%20committee");
    const hits = findings.filter((f) => f.sink?.file === "nginx-combined.log" && f.sink.line === line);
    expect(hits).toHaveLength(0);
  });
});

describe("analyzeLogs — escalation rule", () => {
  it("a probe-path hit that succeeded (2xx) is strictly more severe than its 404 twin", async () => {
    const { findings } = await analyzeLogs([NGINX], { budget: "standard", redact: true, base: FIXTURES });
    const line200 = lineOf('"GET /.env HTTP/1.1" 200');
    const line404 = lineOf('"GET /.env HTTP/1.1" 404');
    const hit200 = findings.find((f) => f.sink?.file === "nginx-combined.log" && f.sink.line === line200 && f.sink.kind === "probe-path");
    const hit404 = findings.find((f) => f.sink?.file === "nginx-combined.log" && f.sink.line === line404 && f.sink.kind === "probe-path");
    expect(hit200).toBeDefined();
    expect(hit404).toBeDefined();
    // Lower SEVERITIES index = more severe.
    expect(severityRank(hit200!.severity)).toBeLessThan(severityRank(hit404!.severity));
    expect(hit200!.message).toContain("succeeded — 2xx");
    expect(hit404!.message).not.toContain("succeeded");
  });
});

describe("analyzeLogs — redaction guarantee", () => {
  const PLANTED_SECRETS = ["hunter2secret", "AKIAIOSFODNN7EXAMPLE", "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"];

  it("no finding anywhere contains a planted secret (redact: true, default)", async () => {
    const { findings } = await analyzeLogs([NGINX, JSONL], { budget: "standard", redact: true, base: FIXTURES });
    const blob = JSON.stringify(findings);
    for (const secret of PLANTED_SECRETS) expect(blob).not.toContain(secret);
    expect(blob).toContain("REDACTED");
  });

  it("--no-redact (redact: false) keeps raw evidence, including the planted secrets", async () => {
    const { findings } = await analyzeLogs([NGINX, JSONL], { budget: "standard", redact: false, base: FIXTURES });
    const blob = JSON.stringify(findings);
    // At least one of the planted secrets must show up in the clear once redaction is off.
    expect(PLANTED_SECRETS.some((s) => blob.includes(s))).toBe(true);
  });
});

describe("analyzeLogs — per-family cap + truncation", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "ultrasec-logs-cap-"));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("caps a single family at 50 findings per run and reports the overflow", async () => {
    const file = join(dir, "flood.log");
    const lines: string[] = [];
    for (let i = 0; i < 80; i++) {
      lines.push(
        `203.0.113.${(i % 200) + 1} - - [10/Oct/2023:15:00:${String(i % 60).padStart(2, "0")} +0000] "GET /search?q=1' OR '${i}'='${i} HTTP/1.1" 200 100 "-" "Mozilla/5.0"`,
      );
    }
    writeFileSync(file, lines.join("\n") + "\n");

    const { findings, truncation } = await analyzeLogs([file], { budget: "standard", redact: true, base: dir });
    const sqliHits = findings.filter((f) => f.sink?.file === "flood.log" && f.sink.kind === "sqli");
    expect(sqliHits).toHaveLength(50);
    expect(truncation.some((t) => t.includes("sqli") && t.includes("30"))).toBe(true);
  });
});

describe("analyzeLogs — stats", () => {
  it("reports files/format/lines and top ips/paths/status counts", async () => {
    const { stats } = await analyzeLogs([NGINX], { budget: "standard", redact: true, base: FIXTURES });
    expect(stats.totalLines).toBe(63);
    expect(stats.files).toHaveLength(1);
    expect(stats.files[0]!.format).toBe("nginx-combined");
    expect(stats.topIps.length).toBeGreaterThan(0);
    expect(stats.topIps.length).toBeLessThanOrEqual(10);
    expect(stats.topPaths.length).toBeGreaterThan(0);
    expect(Object.keys(stats.statusCounts).length).toBeGreaterThan(0);
  });
});
