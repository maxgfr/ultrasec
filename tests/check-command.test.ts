import { describe, it, expect, vi } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runCheck } from "../src/commands/check.js";
import { writeDossier, type Dossier } from "../src/store.js";
import { parseArgs } from "../src/util.js";
import type { Finding, Status } from "../src/types.js";

// Eval closer for the family P0-1/P0-2 proof gap: the semantic gate's NEGATIVE
// arm (grounded-but-unadjudicated → exit 1) is exercised end-to-end THROUGH
// runCheck (not just the check() unit), plus fail-closed when findings.json is
// absent. The gate re-derives its verdict from the persisted statuses — a
// grounded-but-open dossier must never pass --semantic.

const REPO = join(import.meta.dirname, "fixtures", "vuln-express");

function finding(status: Status): Finding {
  // A genuinely grounded citation (src/db.js:6 exists in the fixture).
  return {
    id: "f1",
    category: "taint",
    cwe: "CWE-89",
    title: "SQLi",
    severity: "high",
    confidence: "high",
    message: "m",
    tool: "ultrasec",
    status,
    sink: { file: "src/db.js", line: 6 },
  };
}

function seed(status: Status): string {
  const run = mkdtempSync(join(tmpdir(), "ultrasec-check-"));
  const d: Dossier = {
    manifest: {
      version: "0",
      schemaVersion: 5,
      repo: REPO,
      generatedNote: "",
      languages: ["javascript"],
      toolsRun: [],
      counts: { findings: 1, bySeverity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 } },
    },
    findings: [finding(status)],
    graph: { files: [], edges: [], symbolDefs: {} },
  };
  writeDossier(run, d);
  return run;
}

describe("runCheck — semantic gate arms", () => {
  const silence = () => {
    const o = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    const e = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    return () => {
      o.mockRestore();
      e.mockRestore();
    };
  };

  it("exit 1 on a grounded-but-unadjudicated dossier (negative arm)", () => {
    const run = seed("open");
    const restore = silence();
    expect(runCheck(parseArgs(["check", "--run", run, "--repo", REPO, "--semantic"]))).toBe(1);
    restore();
  });

  it("exit 0 once the candidate is adjudicated (grounding still holds)", () => {
    const run = seed("confirmed");
    const restore = silence();
    expect(runCheck(parseArgs(["check", "--run", run, "--repo", REPO, "--semantic"]))).toBe(0);
    restore();
  });

  it("plain grounding gate passes an open-but-grounded dossier (no --semantic)", () => {
    const run = seed("open");
    const restore = silence();
    expect(runCheck(parseArgs(["check", "--run", run, "--repo", REPO]))).toBe(0);
    restore();
  });

  it("exit 2 when findings.json is absent (fail-closed, not a silent pass)", () => {
    const empty = mkdtempSync(join(tmpdir(), "ultrasec-check-empty-"));
    const restore = silence();
    expect(runCheck(parseArgs(["check", "--run", empty, "--repo", REPO, "--semantic"]))).toBe(2);
    restore();
  });
});
