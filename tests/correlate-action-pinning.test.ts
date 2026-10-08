import { describe, it, expect } from "vitest";
import { correlate } from "../src/tools/correlate.js";
import { makeToolFinding } from "../src/tools/normalize.js";
import type { Finding } from "../src/types.js";

// The engine's agentic-CI pass files an unpinned `uses:` as CWE-829 ("Agentic CI —
// vector J"); semgrep's github-actions-mutable-action-tag files the same line as
// CWE-1357. On one repo that was 79 + 79 rows for 79 lines, each adjudicated
// twice. The two CWEs name the same defect — a third-party component pulled by a
// mutable reference — so a co-located pair is corroboration, not two findings.

const vectorJ = (file: string, line: number): Finding => ({
  id: `vj-${line}`,
  category: "config",
  title: "Agentic CI — vector J: Action not pinned to a commit SHA",
  severity: "medium",
  confidence: "medium",
  message: "uses: actions/checkout@v4",
  tool: "ultrasec",
  sources: ["ultrasec"],
  status: "open",
  cwe: "CWE-829",
  sink: { file, line },
});

const semgrepMutableTag = (file: string, line: number) =>
  makeToolFinding({
    tool: "semgrep",
    category: "sast",
    ident: `yaml.github-actions.security.github-actions-mutable-action-tag:${file}:${line}`,
    title: "yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag",
    severity: "medium",
    message: "mutable tag",
    file,
    line,
    cwe: "CWE-1357",
  });

describe("correlate — action pinning reported by the engine and by semgrep", () => {
  it("folds semgrep's CWE-1357 into the co-located CWE-829 vector J finding", () => {
    const out = correlate([vectorJ(".github/workflows/ci.yml", 21), semgrepMutableTag(".github/workflows/ci.yml", 21)]);
    expect(out).toHaveLength(1);
    expect(out[0]!.id).toBe("vj-21");
    expect(out[0]!.sources).toEqual(["semgrep", "ultrasec"]);
  });

  it("does not fold it onto a different line", () => {
    const out = correlate([vectorJ(".github/workflows/ci.yml", 21), semgrepMutableTag(".github/workflows/ci.yml", 22)]);
    expect(out).toHaveLength(2);
  });

  it("does not make unrelated CWEs equivalent", () => {
    const other = makeToolFinding({
      tool: "semgrep",
      category: "sast",
      ident: "x",
      title: "x",
      severity: "medium",
      message: "m",
      file: ".github/workflows/ci.yml",
      line: 21,
      cwe: "CWE-78",
    });
    expect(correlate([vectorJ(".github/workflows/ci.yml", 21), other])).toHaveLength(2);
  });
});
