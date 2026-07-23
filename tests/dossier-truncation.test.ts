import { describe, it, expect } from "vitest";
import { renderDossierMd, type Dossier } from "../src/store.js";
import type { Finding, Manifest } from "../src/types.js";

// The "Coverage capped" banner is shared across every command that sets
// manifest.truncation.candidates (scan, logs, …). scan's default advice names
// scan-only flags (--max-candidates/--budget/--scope); a command whose cap
// isn't reachable through those flags supplies `truncation.hint` to override
// just the advice sentence. This must be byte-identical to the pre-existing
// scan banner when `hint` is absent, and must render the override verbatim
// (never both) when present.

function finding(): Finding {
  return {
    id: "f1",
    category: "taint",
    title: "SQL injection",
    severity: "high",
    confidence: "low",
    message: "candidate",
    tool: "ultrasec",
    status: "open",
    sink: { file: "src/db.js", line: 10 },
  };
}

function dossier(truncation: NonNullable<Manifest["truncation"]>): Dossier {
  return {
    manifest: {
      version: "0.0.0-test",
      schemaVersion: 5,
      repo: "/tmp/repo",
      generatedNote: "test",
      languages: ["javascript"],
      toolsRun: [],
      counts: { findings: 1, bySeverity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 } },
      truncation,
    },
    findings: [finding()],
    graph: { files: [], edges: [], symbolDefs: {} },
  };
}

describe("renderDossierMd — truncation banner", () => {
  it("scan (no hint) renders the default scan advice — exact banner text, unchanged", () => {
    const md = renderDossierMd(dossier({ candidates: 600, total: 1000 }));
    expect(md).toContain(
      "> ⚠️ **Coverage capped:** **600** of **1000** candidate(s) were not enumerated. Raise `--max-candidates` (or `--budget thorough`) or narrow `--scope` to see the rest.",
    );
  });

  it("a command with `truncation.hint` renders that hint instead of the default scan advice", () => {
    const md = renderDossierMd(
      dossier({
        candidates: 30,
        total: 80,
        hint: "Per-family caps are fixed (not configurable); re-run with `--max-lines` or `--budget thorough` for a larger line budget — see `truncation[]` (stdout/--json) and `LOGSTATS.json` for the full counts.",
      }),
    );
    expect(md).toContain("> ⚠️ **Coverage capped:** **30** of **80** candidate(s) were not enumerated. Per-family caps are fixed");
    expect(md).toContain("--max-lines");
    expect(md).not.toContain("--max-candidates");
    expect(md).not.toContain("narrow `--scope`");
  });
});
