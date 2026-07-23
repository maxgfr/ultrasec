import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { analyzeLogs, KIND_BRUTE_FORCE, KIND_CREDENTIAL_COMPROMISE, KIND_REQUEST_BURST, KIND_SCAN_BEHAVIOR, KIND_RECON_HIT } from "../src/logs/analyze.js";
import { SEVERITIES } from "../src/types.js";

const FIXTURES = join(import.meta.dirname, "fixtures", "logs");
const NGINX = join(FIXTURES, "nginx-combined.log");
const JSONL = join(FIXTURES, "app.jsonl");
const AUTH = join(FIXTURES, "auth.log");

const nginxRaw = readFileSync(NGINX, "utf8").split("\n");
// 1-based line number of the first raw line containing `needle`.
function lineOf(needle: string): number {
  const i = nginxRaw.findIndex((l) => l.includes(needle));
  if (i < 0) throw new Error(`fixture line containing ${JSON.stringify(needle)} not found`);
  return i + 1;
}

const authRaw = readFileSync(AUTH, "utf8").split("\n");
function authLineOf(needle: string): number {
  const i = authRaw.findIndex((l) => l.includes(needle));
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

  // Whole-result guarantee (CRITICAL 1 regression test): `stats` — not just
  // `findings` — is republished verbatim in LOGSTATS.json and `--json`
  // stdout, so it must clear the same bar. `nginx-combined.log` plants the
  // same secret-bearing `.aws/credentials?password=...&key=...` path TWICE
  // (see fixture) specifically so it lands inside `stats.topPaths`'s top-10 —
  // a single occurrence used to fall below the cut and escape this check.
  it("no finding OR stats value anywhere contains a planted secret, including stats.topPaths (redact: true, default)", async () => {
    const { findings, stats } = await analyzeLogs([NGINX, JSONL], { budget: "standard", redact: true, base: FIXTURES });
    const blob = JSON.stringify({ findings, stats });
    for (const secret of PLANTED_SECRETS) expect(blob).not.toContain(secret);
    expect(blob).toContain("REDACTED");
  });

  it("the secret-bearing path that lands in stats.topPaths's top-10 is redacted there too, not just dropped", async () => {
    const { stats } = await analyzeLogs([NGINX], { budget: "standard", redact: true, base: FIXTURES });
    const entry = stats.topPaths.find((p) => p.path.includes("REDACTED"));
    expect(entry).toBeDefined();
    // Both plants of the secret-bearing path (see fixture) count toward one
    // bucket keyed on the REDACTED form — the documented redact-at-add-time
    // choice (see analyze.ts processEvent).
    expect(entry!.count).toBeGreaterThanOrEqual(2);
    const blob = JSON.stringify(stats.topPaths);
    for (const secret of PLANTED_SECRETS) expect(blob).not.toContain(secret);
  });

  it("--no-redact (redact: false) keeps raw evidence, including the planted secrets", async () => {
    const { findings } = await analyzeLogs([NGINX, JSONL], { budget: "standard", redact: false, base: FIXTURES });
    const blob = JSON.stringify(findings);
    // At least one of the planted secrets must show up in the clear once redaction is off.
    expect(PLANTED_SECRETS.some((s) => blob.includes(s))).toBe(true);
  });

  it("--no-redact (redact: false) also keeps the raw secret-bearing path in stats.topPaths", async () => {
    const { stats } = await analyzeLogs([NGINX], { budget: "standard", redact: false, base: FIXTURES });
    const blob = JSON.stringify(stats.topPaths);
    expect(PLANTED_SECRETS.some((s) => blob.includes(s))).toBe(true);
  });

  it("the planted secrets actually produce log-secret-* leak findings (not just silently redacted elsewhere), and those findings are themselves redacted", async () => {
    const { findings } = await analyzeLogs([NGINX, JSONL], { budget: "standard", redact: true, base: FIXTURES });
    const leaks = findings.filter((f) => f.sink?.kind?.startsWith("log-secret-"));
    expect(leaks.length).toBeGreaterThan(0);
    expect(leaks.every((f) => f.cwe === "CWE-532")).toBe(true);
    expect(leaks.every((f) => f.confidence === "low")).toBe(true);
    const blob = JSON.stringify(leaks);
    for (const secret of PLANTED_SECRETS) expect(blob).not.toContain(secret);
    expect(blob).toContain("REDACTED");
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
    expect(stats.totalLines).toBe(64);
    expect(stats.files).toHaveLength(1);
    expect(stats.files[0]!.format).toBe("nginx-combined");
    expect(stats.topIps.length).toBeGreaterThan(0);
    expect(stats.topIps.length).toBeLessThanOrEqual(10);
    expect(stats.topPaths.length).toBeGreaterThan(0);
    expect(Object.keys(stats.statusCounts).length).toBeGreaterThan(0);
  });

  it("reports authFailures/authSuccessAfterFailure/distinctIpsSeen for auth.log", async () => {
    const { stats } = await analyzeLogs([AUTH], { budget: "standard", redact: true, base: FIXTURES });
    // 25 (brute-force ip) + 5+5+5 (scattered) + 4 (invalid-user run) = 44.
    expect(stats.authFailures).toBe(44);
    expect(stats.authSuccessAfterFailure).toBeGreaterThanOrEqual(1);
    expect(stats.distinctIpsSeen).toBeGreaterThan(0);
    expect(stats.distinctIpsOverflowed).toBe(false);
  });
});

describe("analyzeLogs — behavioral aggregation: brute force + credential compromise", () => {
  const BRUTE_FORCE_IP = "198.51.100.200";

  it("fires a brute-force finding for the IP with >=20 failures, citing the first failing line", async () => {
    const { findings } = await analyzeLogs([AUTH], { budget: "standard", redact: true, base: FIXTURES });
    const hit = findings.find((f) => f.sink?.kind === KIND_BRUTE_FORCE);
    expect(hit).toBeDefined();
    expect(hit!.severity).toBe("medium");
    expect(hit!.confidence).toBe("low");
    expect(hit!.sink!.file).toBe("auth.log");
    expect(hit!.sink!.line).toBe(authLineOf(`from ${BRUTE_FORCE_IP} port 51200`));
    expect(hit!.message).toContain(BRUTE_FORCE_IP);
  });

  it("does NOT fire brute-force for IPs below the threshold (scattered failures, invalid-user run)", async () => {
    const { findings } = await analyzeLogs([AUTH], { budget: "standard", redact: true, base: FIXTURES });
    const bruteForceIps = findings.filter((f) => f.sink?.kind === KIND_BRUTE_FORCE).map((f) => f.message);
    expect(bruteForceIps).toHaveLength(1); // only the qualifying IP, never the below-threshold ones
    for (const ip of ["198.51.100.201", "198.51.100.202", "198.51.100.203", "198.51.100.204"]) {
      expect(bruteForceIps.some((m) => m.includes(ip))).toBe(false);
    }
  });

  it("fires a high-severity, needs-human 'possible credential compromise' finding after the brute-force run's success", async () => {
    const { findings } = await analyzeLogs([AUTH], { budget: "standard", redact: true, base: FIXTURES });
    const hit = findings.find((f) => f.sink?.kind === KIND_CREDENTIAL_COMPROMISE);
    expect(hit).toBeDefined();
    expect(hit!.severity).toBe("high");
    expect(hit!.confidence).toBe("low");
    expect(hit!.message.toLowerCase()).toContain("needs-human");
    expect(hit!.message).toContain(BRUTE_FORCE_IP);
    // Cites the first failing line; mentions the success line number in the message.
    const successLine = authLineOf("Accepted password for root");
    expect(hit!.sink!.line).toBe(authLineOf(`from ${BRUTE_FORCE_IP} port 51200`));
    expect(hit!.message).toContain(String(successLine));
  });

  it("line-proxy fallback: syslog has no year, so the window falls back to a line-count proxy — stated honestly in the message", async () => {
    const { findings } = await analyzeLogs([AUTH], { budget: "standard", redact: true, base: FIXTURES });
    const hit = findings.find((f) => f.sink?.kind === KIND_BRUTE_FORCE);
    expect(hit!.message).toContain("line-count proxy window");
    expect(hit!.message).toContain("500");
  });

  it("one finding per (IP, detector) per run — the same run never double-fires brute-force for one IP", async () => {
    const { findings } = await analyzeLogs([AUTH], { budget: "standard", redact: true, base: FIXTURES });
    const hits = findings.filter((f) => f.sink?.kind === KIND_BRUTE_FORCE && f.message.includes(BRUTE_FORCE_IP));
    expect(hits).toHaveLength(1);
  });
});

describe("analyzeLogs — behavioral aggregation: window honored (--window / windowSec)", () => {
  let dir: string;
  let file: string;
  const IP = "203.0.113.230";

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "ultrasec-logs-window-"));
    file = join(dir, "spaced.jsonl");
    // 20 auth-fail events, 5s apart (span: 19*5 = 95s), real ISO-Z timestamps
    // (deterministic epoch — see analyze.ts's parseTsEpochMs).
    const lines: string[] = [];
    for (let i = 0; i < 20; i++) {
      const ts = new Date(Date.UTC(2024, 0, 1, 0, 0, i * 5)).toISOString();
      lines.push(JSON.stringify({ timestamp: ts, message: "login failed for user bob", ip: IP }));
    }
    writeFileSync(file, lines.join("\n") + "\n");
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("does not fire with the default 60s window (95s span never has 20 events inside any 60s slice)", async () => {
    const { findings } = await analyzeLogs([file], { budget: "standard", redact: true, base: dir });
    expect(findings.some((f) => f.sink?.kind === KIND_BRUTE_FORCE)).toBe(false);
  });

  it("fires with a wider --window that covers the whole 95s span", async () => {
    const { findings } = await analyzeLogs([file], { budget: "standard", redact: true, base: dir, windowSec: 120 });
    const hit = findings.find((f) => f.sink?.kind === KIND_BRUTE_FORCE);
    expect(hit).toBeDefined();
    expect(hit!.message).toContain("120s window");
    expect(hit!.message).not.toContain("line-count proxy");
  });
});

describe("analyzeLogs — behavioral aggregation: request burst", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "ultrasec-logs-burst-"));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("fires a low-severity request-burst finding for >300 requests/60s from one IP", async () => {
    const file = join(dir, "burst.log");
    const ip = "203.0.113.240";
    const lines: string[] = [];
    for (let i = 0; i < 301; i++) {
      lines.push(`${ip} - - [10/Oct/2023:15:00:00 +0000] "GET /shop HTTP/1.1" 200 100 "-" "Mozilla/5.0"`);
    }
    writeFileSync(file, lines.join("\n") + "\n");

    const { findings } = await analyzeLogs([file], { budget: "standard", redact: true, base: dir });
    const hit = findings.find((f) => f.sink?.kind === KIND_REQUEST_BURST);
    expect(hit).toBeDefined();
    expect(hit!.severity).toBe("low");
    expect(hit!.message).toContain(ip);
    expect(hit!.message).toContain("301");
  });

  it("does not fire at exactly the 300-request threshold (strict >)", async () => {
    const file = join(dir, "no-burst.log");
    const ip = "203.0.113.241";
    const lines: string[] = [];
    for (let i = 0; i < 300; i++) {
      lines.push(`${ip} - - [10/Oct/2023:15:00:00 +0000] "GET /shop HTTP/1.1" 200 100 "-" "Mozilla/5.0"`);
    }
    writeFileSync(file, lines.join("\n") + "\n");

    const { findings } = await analyzeLogs([file], { budget: "standard", redact: true, base: dir });
    expect(findings.some((f) => f.sink?.kind === KIND_REQUEST_BURST)).toBe(false);
  });
});

describe("analyzeLogs — behavioral aggregation: scanning behavior + recon→hit", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "ultrasec-logs-recon-"));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("fires 'scanning behavior' at >=15 404/403s, then 'recon followed by hit' on a later 2xx probe-path hit", async () => {
    const file = join(dir, "recon.log");
    const ip = "203.0.113.250";
    const lines: string[] = [];
    for (let i = 0; i < 15; i++) {
      const ss = String(i).padStart(2, "0");
      lines.push(`${ip} - - [10/Oct/2023:16:00:${ss} +0000] "GET /admin${i} HTTP/1.1" 404 100 "-" "Mozilla/5.0"`);
    }
    lines.push(`${ip} - - [10/Oct/2023:16:00:16 +0000] "GET /actuator/env HTTP/1.1" 200 3000 "-" "Mozilla/5.0"`);
    writeFileSync(file, lines.join("\n") + "\n");

    const { findings } = await analyzeLogs([file], { budget: "standard", redact: true, base: dir });
    const scan = findings.find((f) => f.sink?.kind === KIND_SCAN_BEHAVIOR);
    expect(scan).toBeDefined();
    expect(scan!.severity).toBe("low");

    const reconHit = findings.find((f) => f.sink?.kind === KIND_RECON_HIT);
    expect(reconHit).toBeDefined();
    expect(reconHit!.severity).toBe("medium");
    expect(reconHit!.sink!.line).toBe(16); // the 2xx line itself
  });

  it("counts 401s toward the scanning-behavior spike, not just 403/404", async () => {
    const file = join(dir, "recon-401.log");
    const ip = "203.0.113.252";
    const lines: string[] = [];
    for (let i = 0; i < 15; i++) {
      const ss = String(i).padStart(2, "0");
      // Mix of 401/403/404 — all three must count toward the same spike.
      const status = i % 3 === 0 ? 401 : i % 3 === 1 ? 403 : 404;
      lines.push(`${ip} - - [10/Oct/2023:16:00:${ss} +0000] "GET /admin${i} HTTP/1.1" ${status} 100 "-" "Mozilla/5.0"`);
    }
    writeFileSync(file, lines.join("\n") + "\n");

    const { findings } = await analyzeLogs([file], { budget: "standard", redact: true, base: dir });
    const scan = findings.find((f) => f.sink?.kind === KIND_SCAN_BEHAVIOR);
    expect(scan).toBeDefined();
    expect(scan!.message).toContain("401/403/404");
  });

  it("does not fire recon→hit when the scan threshold was never reached", async () => {
    const file = join(dir, "no-recon.log");
    const ip = "203.0.113.251";
    const lines: string[] = [
      `${ip} - - [10/Oct/2023:16:00:00 +0000] "GET /missing HTTP/1.1" 404 100 "-" "Mozilla/5.0"`,
      `${ip} - - [10/Oct/2023:16:00:01 +0000] "GET /actuator/env HTTP/1.1" 200 3000 "-" "Mozilla/5.0"`,
    ];
    writeFileSync(file, lines.join("\n") + "\n");

    const { findings } = await analyzeLogs([file], { budget: "standard", redact: true, base: dir });
    expect(findings.some((f) => f.sink?.kind === KIND_RECON_HIT)).toBe(false);
  });
});

describe("analyzeLogs — behavioral aggregation: bounded per-IP state", () => {
  // MAX_TRACKED_IPS (100k) is a hardcoded module constant (same precedent as
  // MAX_DISTINCT for topIps/topPaths) — exercised at real scale here would cost
  // a 100k-line synthetic file per test run for no additional coverage over
  // the class's own logic (see BoundedIpStates.get() — an exact structural
  // mirror of BoundedCounter.add()'s already-proven cap check). This asserts
  // the plumbing (stats fields + no false-positive overflow note) on a normal
  // run instead.
  it("distinctIpsSeen/distinctIpsOverflowed reflect a normal (well under cap) run, with no overflow noted", async () => {
    const { stats, truncation } = await analyzeLogs([AUTH], { budget: "standard", redact: true, base: FIXTURES });
    expect(stats.distinctIpsSeen).toBeGreaterThan(0);
    expect(stats.distinctIpsSeen).toBeLessThanOrEqual(100_000);
    expect(stats.distinctIpsOverflowed).toBe(false);
    expect(truncation.some((t) => t.includes("distinct-IP cap"))).toBe(false);
  });
});

describe("analyzeLogs — secret/PII leak findings", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "ultrasec-logs-secrets-"));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("fires a high-severity, CWE-532 finding for a leaked AWS key, redacted by default", async () => {
    const file = join(dir, "leak.log");
    const ip = "203.0.113.10";
    writeFileSync(file, `${ip} - - [10/Oct/2023:17:00:00 +0000] "GET /debug?key=AKIAABCDEFGHIJKLMNOP HTTP/1.1" 200 10 "-" "Mozilla/5.0"\n`);

    const { findings } = await analyzeLogs([file], { budget: "standard", redact: true, base: dir });
    const hit = findings.find((f) => f.sink?.kind === "log-secret-aws-access-key");
    expect(hit).toBeDefined();
    expect(hit!.severity).toBe("high");
    expect(hit!.cwe).toBe("CWE-532");
    expect(hit!.confidence).toBe("low");
    expect(hit!.message).not.toContain("AKIAABCDEFGHIJKLMNOP");
    expect(hit!.message).toContain("REDACTED");
  });

  it("--no-redact reveals the raw secret in the finding message", async () => {
    const file = join(dir, "leak.log");
    const ip = "203.0.113.11";
    writeFileSync(file, `${ip} - - [10/Oct/2023:17:00:00 +0000] "GET /debug?key=AKIAABCDEFGHIJKLMNOP HTTP/1.1" 200 10 "-" "Mozilla/5.0"\n`);

    const { findings } = await analyzeLogs([file], { budget: "standard", redact: false, base: dir });
    const hit = findings.find((f) => f.sink?.kind === "log-secret-aws-access-key");
    expect(hit!.message).toContain("AKIAABCDEFGHIJKLMNOP");
  });

  it("email bulk heuristic: 4 distinct emails in a file produce no email-leak finding", async () => {
    const file = join(dir, "emails4.log");
    const ip = "203.0.113.12";
    const emails = ["a1@example.com", "b2@example.com", "c3@example.com", "d4@example.com"];
    const lines = emails.map(
      (e, i) => `${ip} - - [10/Oct/2023:17:00:${String(i).padStart(2, "0")} +0000] "GET /contact?email=${e} HTTP/1.1" 200 10 "-" "Mozilla/5.0"`,
    );
    writeFileSync(file, lines.join("\n") + "\n");

    const { findings } = await analyzeLogs([file], { budget: "standard", redact: true, base: dir });
    expect(findings.some((f) => f.sink?.kind === "log-secret-email")).toBe(false);
  });

  it("email bulk heuristic: 6 distinct emails in a file produce at least one email-leak finding", async () => {
    const file = join(dir, "emails6.log");
    const ip = "203.0.113.13";
    const emails = ["a1@example.com", "b2@example.com", "c3@example.com", "d4@example.com", "e5@example.com", "f6@example.com"];
    const lines = emails.map(
      (e, i) => `${ip} - - [10/Oct/2023:17:00:${String(i).padStart(2, "0")} +0000] "GET /contact?email=${e} HTTP/1.1" 200 10 "-" "Mozilla/5.0"`,
    );
    writeFileSync(file, lines.join("\n") + "\n");

    const { findings } = await analyzeLogs([file], { budget: "standard", redact: true, base: dir });
    const emailLeaks = findings.filter((f) => f.sink?.kind === "log-secret-email");
    expect(emailLeaks.length).toBeGreaterThanOrEqual(1);
    expect(emailLeaks.every((f) => f.severity === "medium")).toBe(true);
  });

  it("caps secret/PII leak findings at 25 per file and reports the overflow", async () => {
    const file = join(dir, "secret-flood.log");
    const ip = "203.0.113.14";
    const lines: string[] = [];
    for (let i = 0; i < 30; i++) {
      const ss = String(i % 60).padStart(2, "0");
      lines.push(`${ip} - - [10/Oct/2023:18:00:${ss} +0000] "GET /leak?password=hunter2value${i} HTTP/1.1" 200 10 "-" "Mozilla/5.0"`);
    }
    writeFileSync(file, lines.join("\n") + "\n");

    const { findings, truncation } = await analyzeLogs([file], { budget: "standard", redact: true, base: dir });
    const leaks = findings.filter((f) => f.sink?.file === "secret-flood.log" && f.sink.kind === "log-secret-query-secret");
    expect(leaks).toHaveLength(25);
    expect(truncation.some((t) => t.includes("secret") && t.includes("5"))).toBe(true);
  });
});
