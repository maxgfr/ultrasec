import { describe, it, expect, vi } from "vitest";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { renderSigmaRules } from "../src/logs/sigma.js";
import { ATTACK_SIGNATURES } from "../src/logs/patterns.js";
import { runLogs } from "../src/commands/logs.js";
import { parseArgs } from "../src/util.js";

// WS-A: the SIGMA detection pack emitted by `logs --sigma` — the blue-team mirror
// of `variants`. Rendered from the same data-only catalogs the forensics uses, so
// hunt signatures and shipped detections can't drift; deterministic (no clock).

const LOGS = join(import.meta.dirname, "fixtures", "logs");

describe("sigma pack", () => {
  const pack = renderSigmaRules();
  const docs = pack.split(/^---$/m).filter((d) => d.trim());

  it("emits one rule per attack signature plus scanner-UA and brute-force", () => {
    expect(docs.length).toBe(ATTACK_SIGNATURES.length + 2);
  });

  it("every rule carries the required Sigma fields", () => {
    for (const d of docs) {
      expect(d).toMatch(/\ntitle: /);
      expect(d).toMatch(/\nid: [0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\n/);
      expect(d).toMatch(/\nlogsource:/);
      expect(d).toMatch(/\ndetection:/);
      expect(d).toMatch(/\n {2}condition: /);
      expect(d).toMatch(/\nlevel: (critical|high|medium|low|informational)\n/);
    }
  });

  it("maps families to CWE tags and tags web attacks with ATT&CK", () => {
    expect(pack).toMatch(/cwe\.89/); // sqli
    expect(pack).toMatch(/cwe\.79/); // xss
    expect(pack).toMatch(/cwe\.22/); // traversal
    expect(pack).toMatch(/cwe\.78/); // cmdinj
    expect(pack).toMatch(/attack\.t1190/); // exploit public-facing app
    expect(pack).toMatch(/attack\.t1595/); // scanner UA (active scanning)
    expect(pack).toMatch(/attack\.t1110/); // brute force
  });

  it("carries case-insensitive regexes and the scanner user-agent list", () => {
    expect(pack).toMatch(/c-uri\|re: '\(\?i\)/);
    expect(pack).toMatch(/c-useragent\|re:/);
    expect(pack).toMatch(/sqlmap/);
  });

  it("is deterministic — two renders are byte-identical", () => {
    expect(renderSigmaRules()).toBe(pack);
  });
});

describe("logs --sigma", () => {
  const silence = () => {
    const o = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    const e = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    return () => {
      o.mockRestore();
      e.mockRestore();
    };
  };

  it("writes ultrasec-logs.sigma.yml only when --sigma is passed", async () => {
    const withOut = mkdtempSync(join(tmpdir(), "ultrasec-sigma-"));
    const withoutOut = mkdtempSync(join(tmpdir(), "ultrasec-nosigma-"));
    const restore = silence();
    expect(await runLogs(parseArgs(["logs", LOGS, "--out", withOut, "--sigma"]))).toBe(0);
    expect(await runLogs(parseArgs(["logs", LOGS, "--out", withoutOut]))).toBe(0);
    restore();
    const p = join(withOut, "ultrasec-logs.sigma.yml");
    expect(existsSync(p)).toBe(true);
    expect(readFileSync(p, "utf8")).toMatch(/^---\ntitle: /);
    expect(existsSync(join(withoutOut, "ultrasec-logs.sigma.yml"))).toBe(false);
    // it never contaminates the standard dossier
    expect(existsSync(join(withOut, "findings.json"))).toBe(true);
  });
});
