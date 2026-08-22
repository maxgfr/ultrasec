import { describe, it, expect } from "vitest";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { notebookShadow, scanNotebooks } from "../src/notebooks.js";
import { scanRepo } from "../src/scan.js";
import { buildGraph } from "../src/graph.js";
import { enumerateTaint } from "../src/taint.js";
import { enumerateSinkCandidates } from "../src/sinks.js";
import { lineCount } from "../src/check.js";

// Jupyter notebooks — code an audit could not see because it is not stored as
// code. Measured on a real repository: eight notebooks tracked, zero findings
// ever, and one of them ran `df['action_eventname'].apply(eval)` over rows whose
// values any visitor to the public site could set.
//
// The load-bearing property is line alignment: line N of the shadow is line N of
// the raw JSON, so a citation resolves in the file a reader will actually open
// and `check` will actually count.

const FIXTURE = join(import.meta.dirname, "fixtures", "notebook-eval");
const NOTEBOOK = "analysis.ipynb";
const raw = readFileSync(join(FIXTURE, NOTEBOOK), "utf8");
const rawLines = raw.split("\n");

/** The raw line a given source fragment sits on, 1-based — computed from the
 *  fixture rather than hardcoded, so editing the fixture cannot silently make
 *  these tests assert the wrong lines. */
const rawLineOf = (needle: string): number => {
  const i = rawLines.findIndex((l) => l.includes(needle));
  expect(i, `fixture no longer contains ${needle}`).toBeGreaterThanOrEqual(0);
  return i + 1;
};

describe("notebookShadow", () => {
  const shadow = notebookShadow(raw)!;
  const lines = shadow.text.split("\n");

  it("produces a file with exactly the raw notebook's line count", () => {
    // This is what makes every downstream citation resolvable.
    expect(lines.length).toBe(rawLines.length);
  });

  it("puts each source line on its own raw line number", () => {
    expect(lines[rawLineOf("apply(eval)") - 1]).toBe("parsed = df['action_eventname'].apply(eval)");
    expect(lines[rawLineOf("os.system") - 1]).toBe("os.system('echo ' + parsed.iloc[0])");
    // Indentation inside a cell survives — a def body must still parse as one.
    expect(lines[rawLineOf("read_sql") - 1]).toBe("    return pd.read_sql('select action_eventname from log_link_visit_action', conn)");
  });

  it("blanks IPython magics and shell escapes — they are not Python", () => {
    expect(lines[rawLineOf("%matplotlib") - 1]).toBe("");
    expect(lines[rawLineOf("!pip install") - 1]).toBe("");
    expect(shadow.blanked).toBe(2);
  });

  it("ignores markdown cells", () => {
    expect(shadow.text).not.toContain("Pulls raw event names");
  });

  it("aligns every source line it was given", () => {
    expect(shadow.unaligned).toBe(0);
    expect(shadow.codeLines).toBeGreaterThan(0);
  });

  it("returns undefined for something that is not a notebook", () => {
    expect(notebookShadow("not json at all")).toBeUndefined();
    expect(notebookShadow('{"nbformat": 4}')).toBeUndefined();
  });

  it("aligns a ONE-line string `source`, which nbformat also allows", () => {
    // Six cells of the notebook that motivated this file are one-line strings.
    // The whole cell sits on one raw line, which is exactly the line to cite.
    const nb = { cells: [{ cell_type: "code", source: "os.system(user_input)" }] };
    const text = JSON.stringify(nb, null, 1);
    const s = notebookShadow(text)!;
    expect(s.codeLines).toBe(1);
    expect(s.unaligned).toBe(0);
    const at = text.split("\n").findIndex((l) => l.includes("os.system"));
    expect(s.text.split("\n")[at]).toBe("os.system(user_input)");
  });

  it("counts a MULTI-line string `source` as unaligned instead of guessing", () => {
    // Every one of its lines shares one raw line, so half a cell placed on the
    // wrong lines would be worse than a number that says what was missed.
    const s = notebookShadow(JSON.stringify({ cells: [{ cell_type: "code", source: "import os\nos.system(x)\n" }] }))!;
    expect(s.codeLines).toBe(0);
    expect(s.unaligned).toBe(3);
  });
});

describe("scanNotebooks", () => {
  it("hands back records the ordinary extractor recognises as Python", () => {
    const nb = scanNotebooks(FIXTURE, [NOTEBOOK]);
    expect(nb.stats.found).toBe(1);
    expect(nb.stats.scanned).toBe(1);
    expect(nb.records).toHaveLength(1);
    expect(nb.origin.get(nb.records[0]!.rel)).toBe(NOTEBOOK);
  });

  it("skips Jupyter's checkpoint copies and says how many", () => {
    const nb = scanNotebooks(FIXTURE, [NOTEBOOK, ".ipynb_checkpoints/analysis-checkpoint.ipynb"]);
    expect(nb.stats.checkpoints).toBe(1);
    expect(nb.stats.found).toBe(1);
  });

  it("leaves no temp directory behind", () => {
    const before = scanNotebooks(FIXTURE, [NOTEBOOK]);
    expect(before.records).toHaveLength(1);
    // The shadow dir is removed in a finally; nothing under it survives.
    for (const rec of before.records) expect(existsSync(rec.rel)).toBe(false);
  });

  it("reports the loss instead of throwing when a notebook is unreadable", () => {
    const dir = mkdtempSync(join(tmpdir(), "ultrasec-nb-bad-"));
    writeFileSync(join(dir, "broken.ipynb"), "{ this is not json");
    const nb = scanNotebooks(dir, ["broken.ipynb"]);
    expect(nb.records).toHaveLength(0);
    expect(nb.stats.found).toBe(1);
    expect(nb.stats.scanned).toBe(0);
    expect(nb.stats.note).toContain("nbformat");
  });
});

describe("a notebook is an ordinary scanned file", () => {
  const scan = scanRepo(FIXTURE);

  it("appears in scan.files under its OWN path, as python", () => {
    const f = scan.files.find((x) => x.rel === NOTEBOOK);
    expect(f, "the notebook should be scanned like any other source file").toBeTruthy();
    expect(f!.lang).toBe("python");
    expect(f!.imports.map((i) => i.spec)).toContain("os");
    // Real symbols, real call sites, real line numbers — the AST extractor, not
    // a second-class regex pass.
    expect(f!.symbols.map((s) => s.name)).toContain("load_events");
    const system = f!.calls.find((c) => c.callee === "system");
    expect(system?.receiver).toBe("os");
    expect(system?.line).toBe(rawLineOf("os.system"));
  });

  it("records what the pass found, so silence is never ambiguous", () => {
    expect(scan.notebooks).toBeTruthy();
    expect(scan.notebooks!.found).toBe(1);
    expect(scan.notebooks!.scanned).toBe(1);
  });

  it("yields sink candidates whose citation resolves in the real .ipynb", () => {
    const graph = buildGraph(scan);
    const taint = enumerateTaint(scan, graph).findings;
    const { findings } = enumerateSinkCandidates(scan, taint);
    const inNotebook = findings.filter((f) => f.sink?.file === NOTEBOOK);
    expect(inNotebook.length, "expected the notebook's dangerous calls to be enumerated").toBeGreaterThan(0);

    // The `eval` the audit found by hand, at the line a reader will find it on.
    // It is `.apply(eval)` — a REFERENCE, not a call — so only the line rule can
    // see it; nothing keyed on call nodes can, bandit's B307 included.
    const evalSink = inNotebook.find((f) => f.sink!.kind === "code");
    expect(evalSink, "`.apply(eval)` in a notebook cell should be a code-injection sink").toBeTruthy();
    expect(evalSink!.sink!.line).toBe(rawLineOf("apply(eval)"));

    // …and the ordinary call sink beside it, at its own line.
    const cmd = inNotebook.find((f) => f.sink!.kind === "command");
    expect(cmd, "os.system() in a notebook cell should be a command sink").toBeTruthy();
    expect(cmd!.sink!.line).toBe(rawLineOf("os.system"));

    // And the gate agrees: every cited line exists in the notebook file itself.
    // This is exactly what `check` grades a citation on.
    const total = lineCount(FIXTURE, NOTEBOOK);
    expect(total).not.toBeNull();
    for (const f of inNotebook) {
      expect(f.sink!.line, `${f.sink!.file}:${f.sink!.line} must resolve for check to pass`).toBeGreaterThan(0);
      expect(f.sink!.line).toBeLessThanOrEqual(total!);
    }
  });
});

describe("a repo with no notebooks pays nothing and claims nothing", () => {
  it("reports found: 0 rather than an absent pass", () => {
    const dir = mkdtempSync(join(tmpdir(), "ultrasec-nb-none-"));
    mkdirSync(join(dir, "src"), { recursive: true });
    writeFileSync(join(dir, "src", "a.py"), "import os\n");
    const scan = scanRepo(dir);
    expect(scan.notebooks!.found).toBe(0);
    expect(scan.notebooks!.scanned).toBe(0);
    expect(scan.notebooks!.note).toBeUndefined();
  });
});
