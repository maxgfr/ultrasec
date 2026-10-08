import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { dedupeFindings, loadDossier, writeDossier } from "../src/store.js";
import { appendJournal } from "../src/transcript.js";
import type { Finding } from "../src/types.js";

const dirs: string[] = [];
function fixture(findings: unknown): string {
  const dir = mkdtempSync(join(tmpdir(), "ultrasec-integrity-"));
  dirs.push(dir);
  writeFileSync(join(dir, "manifest.json"), "{}");
  writeFileSync(join(dir, "graph.json"), "{}");
  writeFileSync(join(dir, "findings.json"), JSON.stringify(findings));
  return dir;
}
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
  vi.restoreAllMocks();
});

const row = (id: string, extra: Partial<Finding> = {}): Finding =>
  ({ id, category: "dep", title: `t-${id}`, severity: "high", confidence: "medium", message: "m", tool: "x", status: "open", ...extra }) as Finding;

describe("persisted finding identity", () => {
  it("preserves unique IDs and accepts an empty scan", () => {
    expect(loadDossier(fixture([])).findings).toEqual([]);
    expect(loadDossier(fixture([{ id: "f1" }, { id: "f2" }])).findings.map((f) => f.id)).toEqual(["f1", "f2"]);
  });
  it.each([null, {}, [null], [{}], [{ id: " " }]].map((value) => ({ value })))("rejects malformed finding identities: $value", ({ value }) => {
    expect(() => loadDossier(fixture(value))).toThrow(/findings\.json/);
  });
});

// A duplicated id used to make every downstream command refuse the whole run
// ("findings.json contains duplicate finding id"). One colliding pair out of 354
// findings cost an audit every stage after `scan`. The run is now read, one row
// per id is kept, and the collapse is said out loud — stderr, the manifest, and
// therefore the journal — so nothing disappears quietly.
describe("duplicate finding ids", () => {
  it("keeps one row per id, warns on stderr and records the collapse in the manifest", () => {
    const err = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const d = loadDossier(fixture([row("f1"), row("f2"), row("f1", { title: "other package" })]));
    expect(d.findings.map((f) => f.id)).toEqual(["f1", "f2"]);
    expect(d.findings[0]!.title).toBe("t-f1");
    expect(d.manifest.duplicateIds).toEqual([{ id: "f1", dropped: 1, differing: true }]);
    const printed = err.mock.calls.map((c) => String(c[0])).join("");
    expect(printed).toMatch(/✗ dropped 1 duplicate finding row/);
    expect(printed).toContain("f1");
  });

  it("prefers an adjudicated row over an open one with the same id", () => {
    vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const d = loadDossier(fixture([row("f1"), row("f1", { status: "confirmed", verdict: "supported" })]));
    expect(d.findings).toHaveLength(1);
    expect(d.findings[0]!.status).toBe("confirmed");
  });

  it("an identical copy is collapsed and recorded as not differing", () => {
    const { findings, duplicates } = dedupeFindings([row("a"), row("a")]);
    expect(findings).toHaveLength(1);
    expect(duplicates).toEqual([{ id: "a", dropped: 1, differing: false }]);
  });

  it("never writes duplicate ids: the writer collapses them and recounts", () => {
    vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const dir = fixture([]);
    const manifest = {
      repo: dir,
      version: "0",
      generatedNote: "",
      languages: [],
      toolsRun: [],
      counts: { findings: 3, bySeverity: { critical: 0, high: 3, medium: 0, low: 0, info: 0 } },
    } as never;
    writeDossier(dir, { manifest, findings: [row("a"), row("a"), row("b")], graph: { nodes: [], edges: [] } as never });
    const onDisk = JSON.parse(readFileSync(join(dir, "findings.json"), "utf8")) as Finding[];
    expect(onDisk.map((f) => f.id)).toEqual(["a", "b"]);
    const m = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));
    expect(m.counts.findings).toBe(2);
    expect(m.duplicateIds).toEqual([{ id: "a", dropped: 1, differing: false }]);
  });

  it("the journal records the dropped rows a command printed on stderr", () => {
    const dir = fixture([]);
    appendJournal(dir, {
      command: "ultrasec paths --run x",
      stdout: "no candidate taint paths match.",
      stderr: "ultrasec: ✗ dropped 1 duplicate finding row(s) from findings.json — f1",
      code: 0,
      at: "2026-01-01T00:00:00.000Z",
    });
    expect(readFileSync(join(dir, ".work", "JOURNAL.md"), "utf8")).toContain("✗ dropped 1 duplicate finding row(s)");
  });
});
