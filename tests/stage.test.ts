import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { stageFiles, emitWorklist, collectApplyFiles, readApply, persistFindings } from "../src/stage.js";
import type { Dossier } from "../src/store.js";
import type { Finding } from "../src/types.js";

function tmp(): string {
  return mkdtempSync(join(tmpdir(), "ultrasec-stage-"));
}

describe("stageFiles", () => {
  it("derives conventional todo/md names from a stem", () => {
    expect(stageFiles("REVALIDATE")).toEqual({ todo: "REVALIDATE.todo.json", md: "REVALIDATE.md" });
  });
});

describe("emitWorklist", () => {
  it("writes the JSON todo + the markdown brief and returns the todo path", () => {
    const run = join(tmp(), "nested-run"); // not yet created — emit must mkdir -p
    const items = [{ id: "x", verdict: null }];
    const path = emitWorklist(run, stageFiles("TRIAGE"), items, "# brief\n");
    expect(path).toBe(join(run, "TRIAGE.todo.json"));
    expect(JSON.parse(readFileSync(path, "utf8"))).toEqual(items);
    expect(readFileSync(join(run, "TRIAGE.md"), "utf8")).toBe("# brief\n");
  });
});

describe("collectApplyFiles — apply-file resolution", () => {
  it("splits a comma list (trimming) into resolved paths", () => {
    const files = collectApplyFiles("a.json, b.json ,c.json", /\.json$/);
    expect(files).toHaveLength(3);
    expect(files[0]!.endsWith("/a.json")).toBe(true);
    expect(files[2]!.endsWith("/c.json")).toBe(true);
  });

  it("expands a directory to entries matching the dir regex only", () => {
    const dir = tmp();
    writeFileSync(join(dir, "shard.verdict.0.json"), "[]");
    writeFileSync(join(dir, "shard.verdict.1.json"), "[]");
    writeFileSync(join(dir, "notes.txt"), "ignore me");
    writeFileSync(join(dir, "other.json"), "[]"); // doesn't match the verdict regex
    const files = collectApplyFiles(dir, /verdict.*\.json$/i).sort();
    expect(files).toEqual([join(dir, "shard.verdict.0.json"), join(dir, "shard.verdict.1.json")]);
  });

  it("treats a single non-directory path as one file", () => {
    const f = join(tmp(), "one.json");
    writeFileSync(f, "[]");
    expect(collectApplyFiles(f, /\.json$/)).toEqual([f]);
  });

  it("treats a non-existent single path as one file (caller surfaces the read error)", () => {
    const f = join(tmp(), "missing.json");
    expect(collectApplyFiles(f, /\.json$/)).toEqual([f]);
  });
});

describe("readApply — concatenated parse with tolerant errors", () => {
  it("parses + concatenates every file in order", () => {
    const dir = tmp();
    writeFileSync(join(dir, "a.verdict.json"), JSON.stringify([{ n: 1 }]));
    writeFileSync(join(dir, "b.verdict.json"), JSON.stringify([{ n: 2 }, { n: 3 }]));
    const out = readApply<{ n: number }>(dir, /verdict.*\.json$/i, (raw) => JSON.parse(raw));
    expect(out.map((x) => x.n).sort()).toEqual([1, 2, 3]);
  });

  it("throws with the offending path prefixed on a missing file", () => {
    const f = join(tmp(), "nope.json");
    expect(() => readApply(f, /\.json$/, (raw) => JSON.parse(raw))).toThrow(new RegExp(`^${f.replace(/[/.]/g, "\\$&")}: `));
  });

  it("throws with the offending path prefixed on malformed JSON", () => {
    const f = join(tmp(), "bad.json");
    writeFileSync(f, "{not json");
    expect(() => readApply(f, /\.json$/, (raw) => JSON.parse(raw))).toThrow(new RegExp(`^${f.replace(/[/.]/g, "\\$&")}: `));
  });
});

describe("persistFindings", () => {
  it("rewrites findings.json + manifest with recomputed severity counts, keeping the graph", () => {
    const run = tmp();
    mkdirSync(run, { recursive: true });
    const findings: Finding[] = [
      { id: "a", category: "taint", title: "a", severity: "high", confidence: "low", message: "m", tool: "ultrasec", status: "confirmed" },
      { id: "b", category: "taint", title: "b", severity: "low", confidence: "low", message: "m", tool: "ultrasec", status: "dismissed" },
    ];
    const dossier: Dossier = {
      manifest: {
        version: "0.0.0",
        schemaVersion: 1,
        repo: "/repo",
        generatedNote: "note",
        languages: ["javascript"],
        toolsRun: [],
        counts: { findings: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } },
      },
      findings: [],
      graph: { files: ["src/a.js"], edges: [], symbolDefs: {} },
    };
    persistFindings(run, dossier, findings);
    const written = JSON.parse(readFileSync(join(run, "manifest.json"), "utf8"));
    expect(written.counts).toEqual({ findings: 2, bySeverity: { critical: 0, high: 1, medium: 0, low: 1, info: 0 } });
    expect(written.generatedNote).toBe("note"); // manifest otherwise preserved
    expect(JSON.parse(readFileSync(join(run, "graph.json"), "utf8")).files).toEqual(["src/a.js"]);
    expect(JSON.parse(readFileSync(join(run, "findings.json"), "utf8")).map((f: Finding) => f.id)).toEqual(["a", "b"]);
  });
});
