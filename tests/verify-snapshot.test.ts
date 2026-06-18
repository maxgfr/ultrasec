import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { writeDossier, type Dossier } from "../src/store.js";
import type { Finding, Severity } from "../src/types.js";
import { parseArgs } from "../src/util.js";
import { runVerify } from "../src/commands/verify.js";

// Guards the Phase 0 refactor of `commands/verify.ts` onto the shared stage harness:
// the worklist files it emits and the findings it applies must stay BYTE-IDENTICAL.
// The snapshot is captured against the pre-refactor command and must keep matching.

function finding(id: string, severity: Severity, status: Finding["status"] = "open"): Finding {
  return {
    id,
    category: "taint",
    cwe: "CWE-89",
    title: `finding ${id}`,
    severity,
    confidence: "low",
    message: "candidate",
    tool: "ultrasec",
    status,
    sink: { file: "src/db.js", line: 6 },
    path: [
      { file: "src/server.js", line: 10, why: "source" },
      { file: "src/db.js", line: 6, why: "sink" },
    ],
  };
}

function setup(findings: Finding[]): string {
  const run = mkdtempSync(join(tmpdir(), "ultrasec-verify-snap-"));
  const d: Dossier = {
    manifest: {
      version: "0.0.0",
      schemaVersion: 1,
      repo: "/repo",
      generatedNote: "",
      languages: ["javascript"],
      toolsRun: [],
      counts: { findings: findings.length, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } },
    },
    findings,
    graph: { files: [], edges: [], symbolDefs: {} },
  };
  writeDossier(run, d);
  return run;
}

describe("verify command — byte-identical output (Phase 0 harness refactor guard)", () => {
  let log: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    log = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
  });
  afterEach(() => log.mockRestore());

  it("emit writes a stable VERIFY.todo.json + VERIFY.md", () => {
    const run = setup([finding("a", "high"), finding("b", "low")]);
    runVerify(parseArgs(["verify", "--run", run]));
    expect(readFileSync(join(run, "VERIFY.todo.json"), "utf8")).toMatchSnapshot("VERIFY.todo.json");
    expect(readFileSync(join(run, "VERIFY.md"), "utf8")).toMatchSnapshot("VERIFY.md");
  });

  it("emit --shards writes a sharded todo + the full MD", () => {
    const run = setup([finding("a", "high"), finding("b", "low"), finding("c", "medium")]);
    runVerify(parseArgs(["verify", "--run", run, "--shards", "2", "--shard", "0"]));
    expect(readFileSync(join(run, "VERIFY.todo.0.json"), "utf8")).toMatchSnapshot("VERIFY.todo.0.json");
    expect(readFileSync(join(run, "VERIFY.md"), "utf8")).toMatchSnapshot("VERIFY.md-shard");
  });

  it("apply folds verdicts back into findings.json under the conservative policy", () => {
    const run = setup([finding("a", "high"), finding("b", "low")]);
    const verdicts = join(run, "verdicts.json");
    writeFileSync(
      verdicts,
      JSON.stringify([
        { id: "a", verdict: "supported", exploitPath: "POST /x" },
        { id: "b", verdict: "unsupported", note: "no source" },
      ]),
    );
    runVerify(parseArgs(["verify", "--apply", verdicts, "--run", run]));
    expect(readFileSync(join(run, "findings.json"), "utf8")).toMatchSnapshot("findings.json");
  });
});
