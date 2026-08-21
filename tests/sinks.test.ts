import { describe, it, expect } from "vitest";
import { join } from "node:path";
import { scanRepo } from "../src/scan.js";
import { buildGraph } from "../src/graph.js";
import { enumerateTaint } from "../src/taint.js";
import { enumerateSinkCandidates } from "../src/sinks.js";
import { findSinks, UNRESOLVED_RECEIVER } from "../src/catalog.js";
import { langForFile } from "../src/lang.js";

const FIXTURE = join(import.meta.dirname, "fixtures", "vuln-express");

describe("enumerateSinkCandidates (orphan-sink recall)", () => {
  const scan = scanRepo(FIXTURE);
  const graph = buildGraph(scan);
  const taint = enumerateTaint(scan, graph).findings;

  it("emits a dangerous sink with no source-reachable taint path as a low-confidence sast candidate", () => {
    const { findings } = enumerateSinkCandidates(scan, taint);
    // db.js:11 is getUserSafe's parameterized query() — a real SQL sink the
    // source-gated taint BFS never connects to a source, so it yields zero taint
    // findings today. The orphan-sink layer must surface it for adjudication.
    const orphan = findings.find((f) => f.sink!.file === "src/db.js" && f.sink!.line === 11);
    expect(orphan, "expected an orphan sink candidate at db.js:11").toBeTruthy();
    expect(orphan!.category).toBe("sast");
    expect(orphan!.confidence).toBe("low");
    expect(orphan!.status).toBe("open");
    expect(orphan!.tool).toBe("ultrasec");
    expect(orphan!.cwe).toBe("CWE-89");
    expect(orphan!.sink!.kind).toBe("sql");
    // it is a sink-only candidate — no proven source→sink path
    expect(orphan!.path).toBeUndefined();
    expect(orphan!.source).toBeUndefined();
  });

  it("does NOT re-emit a sink already covered by a taint finding", () => {
    const { findings } = enumerateSinkCandidates(scan, taint);
    for (const t of taint) {
      const dup = findings.find((f) => f.sink!.file === t.sink!.file && f.sink!.line === t.sink!.line && f.sink!.kind === t.sink!.kind);
      expect(dup, `orphan layer duplicated a covered taint sink ${t.sink!.file}:${t.sink!.line}`).toBeFalsy();
    }
  });

  it("rank-then-caps and reports truncation (never silent)", () => {
    const full = enumerateSinkCandidates(scan, []);
    expect(full.total).toBe(full.findings.length);
    expect(full.total).toBeGreaterThanOrEqual(2);
    const capped = enumerateSinkCandidates(scan, [], { maxCandidates: 1 });
    expect(capped.findings.length).toBe(1);
    expect(capped.total).toBe(full.total);
    expect(capped.truncated).toBe(full.total - 1);
  });

  it("produces ids disjoint from taint ids and is idempotent", () => {
    const first = enumerateSinkCandidates(scan, taint).findings;
    const taintIds = new Set(taint.map((f) => f.id));
    expect(first.every((f) => !taintIds.has(f.id))).toBe(true);
    const second = enumerateSinkCandidates(scan, taint).findings;
    expect(second.map((f) => f.id)).toEqual(first.map((f) => f.id));
  });
});

// ── Issue #10 (2): the command sink corroborates before it fires ─────────────
// A single `languages: ["*"]` rule matched `exec` and `run` by NAME, and the
// extractor reports a receiver only when it is a plain identifier — so a regex
// literal, a call chain and a genuinely bare call all arrive identically. On a
// real repo that parses legal-document ids with regexes, 12 of 17 CRITICALs were
// this mistake.
describe("command sinks — ambiguous callees must be corroborated", () => {
  const dir = join(import.meta.dirname, "fixtures", "command-receivers");
  const scan = scanRepo(dir);
  const graph = buildGraph(scan);
  const taint = enumerateTaint(scan, graph, { maxDepth: 8, maxCandidates: 10000 }).findings;
  const orphan = enumerateSinkCandidates(scan, taint).findings;
  const all = [...taint, ...orphan];
  const commandsIn = (file: string) => all.filter((f) => f.cwe === "CWE-78" && f.sink?.file === file);

  it("does not flag RegExp.prototype.exec as OS command injection", () => {
    expect(commandsIn("fp-regex.ts")).toEqual([]);
  });

  it("does not flag a call to a function the file defines itself", () => {
    // `run()` is declared at fp-local-run.ts:3 and called at :9. A local
    // definition wins over the catalog entry for the same name.
    expect(commandsIn("fp-local-run.ts")).toEqual([]);
  });

  it("lets a local definition outrank a corroborating import", () => {
    // fp-local-run.py imports subprocess AND declares its own `run`. The bare
    // `run(job, "target")` at :11 is the local one — shadowing is a language
    // rule, not a hint — while `subprocess.run` at :15 is the real sink.
    const py = commandsIn("fp-local-run.py");
    expect(py.map((f) => f.sink!.line)).toEqual([15]);
  });

  it("still flags a member call on the process module", () => {
    expect(commandsIn("tp-member.js").map((f) => f.severity)).toContain("critical");
  });

  it("still flags a bare call corroborated by a named import", () => {
    expect(commandsIn("tp-named.js").map((f) => f.severity)).toContain("critical");
  });

  it("still flags a callee bound to a const — the local-definition gate is callables only", () => {
    // `const spawn = require("child_process").spawn` is a `const` SYMBOL named
    // `spawn`. Treating that as a local definition would silence a real sink.
    expect(commandsIn("tp-const-binding.js").map((f) => f.severity)).toContain("critical");
  });

  it("still flags PHP's bare process builtins, which have no receiver at all", () => {
    const php = commandsIn("tp-bare.php");
    expect(php.length).toBeGreaterThanOrEqual(3);
    expect(php.every((f) => f.severity === "critical")).toBe(true);
  });

  it("still flags `from subprocess import run`", () => {
    expect(commandsIn("tp-from-import.py").map((f) => f.severity)).toContain("critical");
  });

  it("still flags Go's exec.Command", () => {
    expect(commandsIn("tp-go.go").map((f) => f.severity)).toContain("critical");
  });
});

// When imports could not be extracted at all — the regex tier — an
// uncorroborated ambiguous callee is NOT dropped. Silently losing a real sink
// because tree-sitter was unavailable would trade one failure mode for another.
describe("command sinks — uncorroborated is downgraded, never dropped", () => {
  const js = langForFile("a.ts")!;

  it("downgrades a bare ambiguous callee when no imports were visible", () => {
    const hits = findSinks(js, [{ callee: "exec", line: 1 }], undefined, []);
    const cmd = hits.find((h) => h.kind === "command");
    expect(cmd, "expected the rule to still match").toBeTruthy();
    expect(cmd!.severity).toBe("medium");
    expect(cmd!.downgraded).toBe(UNRESOLVED_RECEIVER);
  });

  it("drops it outright once imports ARE visible and none corroborate", () => {
    const hits = findSinks(js, [{ callee: "exec", line: 1 }], undefined, [{ spec: "./util" }]);
    expect(hits.some((h) => h.kind === "command")).toBe(false);
  });

  it("fires at full severity, undowngraded, when the import corroborates", () => {
    const hits = findSinks(js, [{ callee: "exec", line: 1 }], undefined, [{ spec: "child_process" }]);
    const cmd = hits.find((h) => h.kind === "command")!;
    expect(cmd.severity).toBe("critical");
    expect(cmd.downgraded).toBeUndefined();
  });
});
