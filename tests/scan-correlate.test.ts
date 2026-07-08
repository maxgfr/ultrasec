import { describe, it, expect, vi } from "vitest";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { runScan } from "../src/commands/scan.js";
import { makeToolFinding } from "../src/tools/normalize.js";
import { parseArgs } from "../src/util.js";
import type { Finding } from "../src/types.js";

// Regression for the eval's P0.3a: `scan` used to correlate only INSIDE
// orchestrate (tool findings alone) and concatenate taint/orphan-sink candidates
// afterwards — so a tool finding sitting exactly on a taint node was never folded
// in, and the same bug shipped twice in the report. These tests drive runScan
// end-to-end with a mocked orchestrate to prove the merged set is correlated.

const FIXTURE = resolve(__dirname, "fixtures/vuln-express");

const { orchestrateMock } = vi.hoisted(() => ({ orchestrateMock: vi.fn() }));
vi.mock("../src/tools/run.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("../src/tools/run.js")>();
  return { ...original, orchestrate: orchestrateMock };
});

function loadFindings(out: string): Finding[] {
  return JSON.parse(readFileSync(join(out, "findings.json"), "utf8")) as Finding[];
}

describe("scan — correlates taint, orphan-sink and tool findings in one pass", () => {
  it("folds a co-located same-CWE tool finding into the taint candidate instead of double-reporting", async () => {
    const semgrep = makeToolFinding({
      tool: "semgrep",
      category: "sast",
      ident: "javascript.lang.security.detect-child-process:src/report.js:5",
      title: "javascript.lang.security.detect-child-process",
      severity: "high",
      message: "Detected child_process exec with a non-literal argument.",
      file: "src/report.js",
      line: 5, // the vuln-express execSync sink line — also the taint finding's sink
      cwe: "CWE-78",
    });
    orchestrateMock.mockReturnValueOnce({ findings: [semgrep], toolsRun: ["semgrep"], results: [] });

    const out = mkdtempSync(join(tmpdir(), "ultrasec-scan-corr-"));
    const code = await runScan(parseArgs(["scan", "--repo", FIXTURE, "--out", out, "--no-enrich"]));
    expect(code).toBe(0);
    expect(orchestrateMock).toHaveBeenCalled();

    const findings = loadFindings(out);
    const cwe78 = findings.filter((f) => f.cwe === "CWE-78");
    expect(cwe78).toHaveLength(1); // one finding for one bug — the standalone semgrep entry is consumed
    const t = cwe78[0]!;
    expect(t.tool).toBe("ultrasec"); // the taint candidate is the survivor
    expect(t.sources).toEqual(["semgrep", "ultrasec"]); // corroboration recorded
    expect(t.confidence).toBe("high"); // ≥2 sources
    expect(t.sink).toMatchObject({ file: "src/report.js", line: 5 }); // path identity untouched
    expect(t.path?.length).toBeGreaterThan(1);
  });

  it("folds a co-located same-CWE tool finding into an orphan-sink candidate too (--sinks)", async () => {
    // db.js:11 (`getUserSafe`'s parameterized query) is not reachable from a source,
    // so it only surfaces under the opt-in orphan-sink pass — as tool:"ultrasec",
    // category:"sast", CWE-89. A scanner flagging the same line+CWE corroborates it.
    const semgrep = makeToolFinding({
      tool: "semgrep",
      category: "sast",
      ident: "javascript.lang.security.audit.sqli:src/db.js:11",
      title: "javascript.lang.security.audit.sqli",
      severity: "medium",
      message: "Possible SQL injection.",
      file: "src/db.js",
      line: 11,
      cwe: "CWE-89",
    });
    orchestrateMock.mockReturnValueOnce({ findings: [semgrep], toolsRun: ["semgrep"], results: [] });

    const out = mkdtempSync(join(tmpdir(), "ultrasec-scan-corr-"));
    const code = await runScan(parseArgs(["scan", "--repo", FIXTURE, "--out", out, "--no-enrich", "--sinks"]));
    expect(code).toBe(0);

    const findings = loadFindings(out);
    const at11 = findings.filter((f) => f.sink?.file === "src/db.js" && f.sink.line === 11);
    expect(at11).toHaveLength(1); // semgrep entry consumed into the orphan-sink candidate
    expect(at11[0]!.tool).toBe("ultrasec");
    expect(at11[0]!.sources).toContain("semgrep");
  });
});
