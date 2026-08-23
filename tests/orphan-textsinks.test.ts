import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanRepo } from "../src/scan.js";
import { enumerateSinkCandidates } from "../src/sinks.js";

// ── Assignment sinks need orphan coverage too ──────────────────────────────
//
// `enumerateSinkCandidates` enumerated only CALL sinks for its whole life,
// while the taint pass has always used call sinks AND assignment sinks. So the
// entire assignment family (`dangerouslySetInnerHTML`, `innerHTML =`, `v-html`,
// `[innerHTML]`, `.src =`) only ever surfaced when a source could be linked to
// it — which is precisely the case a RECALL pass exists for.
//
// Measured on a real audit: seven `dangerouslySetInnerHTML` in the audited tree,
// all seven matched by `findTextSinks`, **zero** reported. Six were later found
// by hand; the seventh by an external scanner whose own rule was too narrow. A
// second audit of an unrelated repo lost a latent one the same way.

function repoWith(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "ultrasec-textsink-"));
  for (const [rel, body] of Object.entries(files)) writeFileSync(join(dir, rel), body);
  return dir;
}

describe("orphan sinks — assignment shapes, not just calls", () => {
  // No source anywhere: the values are editorial content arriving as props.
  // This is the exact shape that produced nothing at all before.
  const dir = repoWith({
    "Form.tsx": `export function Form({ value, message }) {
  return (
    <div>
      <div dangerouslySetInnerHTML={{ __html: value }} />
      <div dangerouslySetInnerHTML={{ __html: message.contentAgreement }} />
    </div>
  );
}
`,
    "legacy.js": `export function render(el, html) {\n  el.innerHTML = html;\n}\n`,
    "cmd.js": `const cp = require("child_process");\nexport function go(x) {\n  cp.exec(x);\n}\n`,
  });
  const orphans = enumerateSinkCandidates(scanRepo(dir), []).findings;

  it("reports every dangerouslySetInnerHTML that no source reaches", () => {
    const xss = orphans.filter((f) => f.cwe === "CWE-79" && f.sink?.file === "Form.tsx");
    expect(xss.map((f) => f.sink!.line).sort((a, b) => a - b)).toEqual([4, 5]);
  });

  it("reports a bare innerHTML assignment too", () => {
    expect(orphans.some((f) => f.cwe === "CWE-79" && f.sink?.file === "legacy.js")).toBe(true);
  });

  it("phrases an assignment sink as a value, not as a call", () => {
    // Its `callee` is a label ("framework HTML bypass"), so the call phrasing
    // would have read "framework HTML bypass() sink".
    const xss = orphans.find((f) => f.cwe === "CWE-79")!;
    expect(xss.title).not.toContain("()");
    expect(xss.reachability).toBe("unproven");
  });

  it("still carries the call sinks it always did", () => {
    expect(orphans.some((f) => f.cwe === "CWE-78" && f.sink?.file === "cmd.js")).toBe(true);
  });

  it("does not double-report a sink the taint pass already grounded", () => {
    const grounded = orphans.filter((f) => f.sink?.file === "Form.tsx");
    const covered = enumerateSinkCandidates(scanRepo(dir), grounded).findings;
    expect(covered.some((f) => f.sink?.file === "Form.tsx")).toBe(false);
  });
});

// ── A sourceless class must not need the opt-in flag ───────────────────────
//
// `findSinks` is source-gated, so a rule with no untrusted SOURCE to trace is
// not merely left unproven by the default scan — it is hidden by it. CWE-407
// shipped that way: it arrived in the same commit as CWE-209, for the same
// stated reason (the super-linear cost is inside the library the caller called,
// so no source exists to find), but CWE-209 was written as a line-shape rule and
// CWE-407 as a sink rule. The audit finding it was built for, an unbounded
// `fuzz.extract` on a search query, was therefore invisible to the documented
// scan command and appeared only under `--sinks`, which the docs use nowhere.
describe("orphan sinks — sourceless classes are enumerated without --sinks", () => {
  const dir = repoWith({
    // No untrusted read anywhere: the query arrives as a plain parameter.
    "search.js": 'const fuzz = require("fuzzball");\nexport function rank(q, all) {\n  return fuzz.extract(q, all, { scorer: fuzz.ratio });\n}\n',
    // An ordinary orphan sink, for contrast: it needs the flag.
    "db.js": 'import { pool } from "./pool.js";\nexport function find(name) {\n  return pool.query("SELECT * FROM t WHERE n = " + name);\n}\n',
  });
  const scan = scanRepo(dir);

  it("emits the sourceless class when the pass is narrowed to it", () => {
    const { findings } = enumerateSinkCandidates(scan, [], { onlyKinds: new Set(["algodos"]) });
    expect(findings.map((f) => f.cwe)).toEqual(["CWE-407"]);
    expect(findings[0]!.sink!.file).toBe("search.js");
  });

  it("does NOT drag ordinary orphan sinks in with it", () => {
    const { findings } = enumerateSinkCandidates(scan, [], { onlyKinds: new Set(["algodos"]) });
    expect(findings.some((f) => f.cwe === "CWE-89")).toBe(false);
  });

  it("still emits everything when the pass is not narrowed", () => {
    const { findings } = enumerateSinkCandidates(scan, []);
    const cwes = new Set(findings.map((f) => f.cwe));
    expect(cwes.has("CWE-407")).toBe(true);
    expect(cwes.has("CWE-89")).toBe(true);
  });

  it("does not claim a missing source path for a class that has none", () => {
    const { findings } = enumerateSinkCandidates(scan, [], { onlyKinds: new Set(["algodos"]) });
    expect(findings[0]!.title).not.toContain("no source path found");
    expect(findings[0]!.message).toContain("no source to trace");
  });
});
