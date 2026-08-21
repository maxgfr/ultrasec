import { describe, it, expect } from "vitest";
import { join } from "node:path";
import { scanRepo } from "../src/scan.js";
import { buildGraph } from "../src/graph.js";
import { enumerateTaint } from "../src/taint.js";
import { enumerateSinkCandidates } from "../src/sinks.js";
import { findSinks, UNRESOLVED_RECEIVER, findTextSinks, isConstantAssignment } from "../src/catalog.js";
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

// ── Issue #10 (2): gating must not cost CROSS-LANGUAGE recall ────────────────
// Splitting one `languages: ["*"]` rule into gated per-language ones is exactly
// the kind of change that quietly loses a language. One file per real-world
// process-execution shape, and every one of them must still be CRITICAL.
describe("command sinks — every language's real shape still fires", () => {
  const dir = join(import.meta.dirname, "fixtures", "command-recall");
  const scan = scanRepo(dir);
  const taint = enumerateTaint(scan, buildGraph(scan), { maxDepth: 8, maxCandidates: 10000 }).findings;
  const orphan = enumerateSinkCandidates(scan, taint).findings;
  const all = [...taint, ...orphan];
  const criticalsIn = (file: string) => all.filter((f) => f.cwe === "CWE-78" && f.sink?.file === file && f.severity === "critical").length;

  const CASES: [string, string, number][] = [
    ["Runtime.java", "Runtime.getRuntime().exec(cmd)", 1],
    ["Builder.java", "new ProcessBuilder(…)", 1],
    ["cmd.rs", "Command::new(…) (std::process)", 1],
    ["cs_proc.cs", "Process.Start(…) (System.Diagnostics)", 1],
    ["go_cmd.go", "exec.Command(…) (os/exec)", 1],
    ["shell.rb", "bare system(cmd)", 1],
    ["os_system.py", "os.system / os.popen", 2],
    ["sub_call.py", "subprocess.call / check_output", 2],
    ["php_bare.php", "PHP's six bare builtins", 6],
    ["js_forms.js", "cp.exec / cp.spawn / execSync / spawnSync", 4],
  ];

  for (const [file, shape, want] of CASES) {
    it(`still flags ${shape}`, () => {
      expect(criticalsIn(file)).toBe(want);
    });
  }
});

// `requireModule` needles are compared against LOWERCASED import specs, so a
// capitalised module name never matched and its rule silently stopped firing.
describe("requireModule matches case-insensitively", () => {
  const cs = langForFile("a.cs")!;

  it("matches a capitalised module name", () => {
    const hits = findSinks(cs, [{ callee: "Start", receiver: "Process", line: 1 }], undefined, [{ spec: "System.Diagnostics" }]);
    expect(hits.some((h) => h.kind === "command")).toBe(true);
  });

  it("still matches when the extractor lowercases it", () => {
    const hits = findSinks(cs, [{ callee: "Start", receiver: "Process", line: 1 }], undefined, [{ spec: "system.diagnostics" }]);
    expect(hits.some((h) => h.kind === "command")).toBe(true);
  });
});

const js = langForFile("x.js")!;

describe("window.open is navigation, not a filesystem read", () => {
  // `open` sits in the CWE-22 path rule, which declares no `receivers` — and the
  // receiver check is `if (rule.receivers && c.receiver && …)`, inert when a rule
  // has none. So `window.open(url)` matched "Path traversal / archive extraction
  // (zip-slip)" at HIGH, and the first-match `break` blocked any better rule.
  it("classifies window.open as CWE-601, not CWE-22", () => {
    const hits = findSinks(js, [{ callee: "open", receiver: "window", line: 1 }]);
    expect(hits.map((h) => h.cwe)).toEqual(["CWE-601"]);
    expect(hits[0]!.kind).toBe("redirect");
  });

  it("covers the other global receivers", () => {
    for (const receiver of ["globalThis", "self", "top", "parent"]) {
      expect(findSinks(js, [{ callee: "open", receiver, line: 1 }])[0]!.cwe, receiver).toBe("CWE-601");
    }
  });

  it("still treats a filesystem open as path traversal", () => {
    const hits = findSinks(js, [{ callee: "open", receiver: "fs", line: 1 }]);
    expect(hits[0]!.cwe).toBe("CWE-22");
  });

  it("a bare open() is still path traversal — the new rule requires a receiver", () => {
    expect(findSinks(js, [{ callee: "open", line: 1 }])[0]!.cwe).toBe("CWE-22");
  });
});

describe("a URL/HTML attribute assigned a CONSTANT is not a sink", () => {
  // Reachability is "a source at or above the sink line in the same file", so a
  // literal `script.src = "https://…"` was reported as DOM XSS because an
  // unrelated `location.hash` read appeared earlier in the file.
  it("drops a literal src assignment", () => {
    expect(findTextSinks(js, 'script.src = "https://www.googletagmanager.com/gtag/js?id=DC-3048978";')).toEqual([]);
  });

  it("keeps a dynamic one", () => {
    expect(findTextSinks(js, "script.src = userUrl;")).toHaveLength(1);
    expect(findTextSinks(js, "script.src = `${base}/x.js`;")).toHaveLength(1);
    expect(findTextSinks(js, 'script.src = "https://cdn/" + name;')).toHaveLength(1);
  });

  it("drops a literal innerHTML but keeps an interpolated one", () => {
    expect(findTextSinks(js, 'el.innerHTML = "<b>static</b>";')).toEqual([]);
    expect(findTextSinks(js, "el.innerHTML = `<b>${name}</b>`;")).toHaveLength(1);
  });

  // The gate must NOT reach the framework rule: there the quotes delimit an HTML
  // attribute and its contents are the expression.
  it("never drops a Vue/Angular template binding", () => {
    expect(findTextSinks(js, '<div v-html="userHtml"></div>')).toHaveLength(1);
    expect(findTextSinks(js, '<div [innerHTML]="userHtml"></div>')).toHaveLength(1);
  });

  it("keeps anything it cannot prove constant", () => {
    // value continued on the next line
    expect(findTextSinks(js, "script.src =")).toHaveLength(1);
    expect(isConstantAssignment("")).toBe(false);
    expect(isConstantAssignment(' "a" + b')).toBe(false);
    expect(isConstantAssignment(" `${x}`")).toBe(false);
    expect(isConstantAssignment(' "plain";')).toBe(true);
  });
});
