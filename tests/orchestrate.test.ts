import { existsSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { Script } from "node:vm";
import { describe, expect, it, vi } from "vitest";
import { dispatch } from "../src/cli.js";
import { BATCH_SIZE, PHASES, SMALL_WORKLIST, listPhases, orchestrateRun } from "../src/orchestrate.js";
import type { Finding } from "../src/types.js";
import type { VerifyItem } from "../src/verify.js";
import { parseArgs } from "../src/util.js";

// The orchestrate suite builds its fixtures THROUGH THE REAL ENGINE (offline:
// `--tools none --no-enrich`): scan the labelled vuln-express fixture → findings,
// verify/revalidate/investigate emit their real worklists — so the phases fan out
// over exactly the artifacts the pipeline produces, not hand-written stand-ins.
const REPO = join(import.meta.dirname, "fixtures", "vuln-express");
const ENGINE = "/opt/skills/ultrasec/scripts/ultrasec.mjs";

/** Run an engine command in-process, silencing its stdout/stderr. */
async function engine(...argv: string[]): Promise<number> {
  const out = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
  const err = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  try {
    return await dispatch(argv[0], parseArgs(argv));
  } finally {
    out.mockRestore();
    err.mockRestore();
  }
}

const findings = (run: string): Finding[] => JSON.parse(readFileSync(join(run, "findings.json"), "utf8")) as Finding[];

interface RunOpts {
  scan?: boolean;
  /** Ingest N extra grounded discoveries (real `investigate --apply`) so the open worklist grows. */
  extraOpen?: number;
  /** Adjudicate via a real `verify --apply`: "some" leaves one candidate open; "all" leaves none. */
  confirm?: "some" | "all";
  verify?: boolean;
  revalidate?: boolean;
  investigate?: boolean;
}

/** A run dir holding real engine-written artifacts (same writers as the pipeline). */
async function makeRun(opts: RunOpts = {}): Promise<string> {
  const run = mkdtempSync(join(tmpdir(), "usec-orch-"));
  if (!opts.scan) return run;
  expect(await engine("scan", "--repo", REPO, "--out", run, "--tools", "none", "--no-enrich")).toBe(0);

  if (opts.extraOpen) {
    const discoveries = Array.from({ length: opts.extraOpen }, (_, i) => ({
      title: `Missing authz check ${i + 1}`,
      category: "authz",
      severity: "medium",
      message: `Route handler ${i + 1} performs no authorization check.`,
      file: "src/server.js",
      line: (i % 20) + 1,
    }));
    const p = join(run, "extra.INVESTIGATE.json");
    writeFileSync(p, JSON.stringify(discoveries));
    expect(await engine("investigate", "--apply", p, "--run", run, "--repo", REPO)).toBe(0);
  }

  if (opts.confirm) {
    // Deterministic verdicts over the fixture's 3 taint candidates, by severity.
    const bySev = new Map(findings(run).map((f) => [f.severity, f.id]));
    const verdicts =
      opts.confirm === "all"
        ? [
            { id: bySev.get("critical"), verdict: "supported", note: "t", exploitPath: "GET /report?name=;id" },
            { id: bySev.get("high"), verdict: "supported", note: "t", exploitPath: "GET /user?id=1 OR 1=1" },
            { id: bySev.get("medium"), verdict: "partial", note: "t" },
          ]
        : [
            { id: bySev.get("critical"), verdict: "supported", note: "t", exploitPath: "GET /report?name=;id" },
            { id: bySev.get("high"), verdict: "partial", note: "t" },
          ];
    const p = join(run, "seed.verdicts.json");
    writeFileSync(p, JSON.stringify(verdicts));
    expect(await engine("verify", "--apply", p, "--run", run)).toBe(0);
  }

  if (opts.verify) expect(await engine("verify", "--run", run)).toBe(0);
  if (opts.revalidate) expect(await engine("revalidate", "--run", run, "--repo", REPO)).toBe(0);
  if (opts.investigate) expect(await engine("investigate", "--run", run, "--repo", REPO)).toBe(0);
  return run;
}

/** The full-pipeline run every emission test reuses (built once — the engine is real but not free). */
let fullRunPromise: Promise<string> | undefined;
function fullRun(): Promise<string> {
  fullRunPromise ??= makeRun({ scan: true, confirm: "some", verify: true, revalidate: true, investigate: true });
  return fullRunPromise;
}

const wf = (run: string, phase: string) => join(run, "orchestration", `${phase}.workflow.mjs`);
const readWf = (run: string, phase: string) => readFileSync(wf(run, phase), "utf8");
const stable = (src: string, run: string) => src.replaceAll(run, "<RUN>").replaceAll(REPO, "<REPO>").replaceAll(ENGINE, "<ENGINE>");

describe("orchestrate — listPhases", () => {
  it("reports all phases not ready on an empty run, naming the producing command", async () => {
    const run = await makeRun();
    const phases = listPhases(run, ENGINE);
    expect(phases.map((p) => p.name)).toEqual(["adjudicate", "verify", "revalidate", "investigate"]);
    for (const p of phases) {
      expect(p.ready).toBe(false);
      expect(p.items).toBe(0);
    }
    expect(phases[0]!.prerequisite).toContain("scan --repo");
    expect(phases[1]!.prerequisite).toContain("verify --run");
    expect(phases[2]!.prerequisite).toContain("revalidate --run");
    expect(phases[3]!.prerequisite).toContain("investigate --run");
  });

  it("reports ready phases with real item counts and absolute worklist paths", async () => {
    const run = await fullRun();
    const phases = listPhases(run, ENGINE);
    // Fixture: 3 taint candidates; confirm "some" ⇒ 1 confirmed · 1 needs-human · 1 open.
    expect(phases[0]).toMatchObject({ name: "adjudicate", ready: true, items: 1 });
    expect(phases[1]).toMatchObject({ name: "verify", ready: true, items: 2 }); // open + needs-human
    expect(phases[2]).toMatchObject({ name: "revalidate", ready: true, items: 2 }); // confirmed + needs-human
    expect(phases[3]).toMatchObject({ name: "investigate", ready: true, items: 1 }); // one region: src
    for (const p of phases) expect(isAbsolute(p.worklist)).toBe(true);
  });

  it("adjudicate fans out over OPEN candidates only — adjudicated ids never re-enter the batch", async () => {
    const run = await makeRun({ scan: true, confirm: "some" });
    const all = findings(run);
    const open = all.filter((f) => f.status === "open").map((f) => f.id);
    const settled = all.filter((f) => f.status !== "open").map((f) => f.id);
    const adj = listPhases(run, ENGINE)[0]!;
    expect(adj.ids.sort()).toEqual(open.sort());
    for (const id of settled) expect(adj.ids).not.toContain(id);
  });
});

describe("orchestrate — emitted workflow", () => {
  it("emits one workflow per ready phase, plus contracts and the runbook", async () => {
    const run = await fullRun();
    const res = orchestrateRun(run, ENGINE);
    expect(res.exitCode).toBe(0);
    for (const phase of PHASES) expect(existsSync(wf(run, phase))).toBe(true);
    expect(existsSync(join(run, "orchestration", "RUNBOOK.md"))).toBe(true);
    for (const role of ["analyzer", "skeptic", "revalidator", "hunter"]) {
      expect(existsSync(join(run, "orchestration", "agents", `${role}.md`))).toBe(true);
    }
  });

  it("parses as JavaScript the way the Workflow harness evaluates it (meta export + async body)", async () => {
    const run = await fullRun();
    orchestrateRun(run, ENGINE);
    for (const phase of PHASES) {
      const [metaLine, ...body] = readWf(run, phase).split("\n");
      expect(() => new Script(metaLine!.replace("export const meta =", "const meta ="))).not.toThrow();
      expect(() => new Script(`(async () => {\n${body.join("\n")}\n})`)).not.toThrow();
    }
  });

  it("meta is a pure JSON literal on line 1 (name, description, phases)", async () => {
    const run = await fullRun();
    orchestrateRun(run, ENGINE);
    const first = readWf(run, "adjudicate").split("\n")[0]!;
    expect(first.startsWith("export const meta = ")).toBe(true);
    const meta = JSON.parse(first.replace("export const meta = ", "")) as { name: string; description: string; phases: unknown[] };
    expect(meta.name).toBe("ultrasec-adjudicate");
    expect(meta.description.length).toBeGreaterThan(0);
    expect(Array.isArray(meta.phases)).toBe(true);
  });

  it("never contains Date.now / Math.random / new Date (forbidden under the Workflow tool)", async () => {
    const run = await fullRun();
    orchestrateRun(run, ENGINE);
    for (const phase of PHASES) {
      const src = readWf(run, phase);
      expect(src).not.toContain("Date.now(");
      expect(src).not.toContain("Math.random(");
      expect(src).not.toContain("new Date(");
    }
  });

  it("injects absolute RUN/ENGINE/WORKLIST constants matching the run", async () => {
    const run = await fullRun();
    orchestrateRun(run, ENGINE);
    const src = readWf(run, "verify");
    for (const name of ["RUN", "ENGINE", "WORKLIST"]) {
      const m = src.match(new RegExp(`const ${name} = "([^"]+)"`));
      expect(m, `const ${name} missing`).not.toBeNull();
      expect(isAbsolute(m![1]!)).toBe(true);
    }
    expect(src).toContain(JSON.stringify(join(run, "VERIFY.todo.json")));
    expect(src).toContain(JSON.stringify(ENGINE));
    expect(readWf(run, "adjudicate")).toContain(JSON.stringify(join(run, "findings.json")));
  });

  it("injects the REAL current worklist ids — a doctored worklist shows up on re-emit", async () => {
    const run = await makeRun({ scan: true, verify: true });
    orchestrateRun(run, ENGINE);
    expect(readWf(run, "verify")).not.toContain("fake9999");
    const todoPath = join(run, "VERIFY.todo.json");
    const items = JSON.parse(readFileSync(todoPath, "utf8")) as VerifyItem[];
    items.push({ ...items[0]!, id: "fake9999" });
    writeFileSync(todoPath, JSON.stringify(items, null, 2));
    orchestrateRun(run, ENGINE);
    expect(readWf(run, "verify")).toContain("fake9999");
  });

  it("is deterministic — two runs over the same state emit byte-identical artifacts", async () => {
    const run = await fullRun();
    const emit = () => {
      orchestrateRun(run, ENGINE);
      return PHASES.map((p) => readWf(run, p)).join("\0") + readFileSync(join(run, "orchestration", "RUNBOOK.md"), "utf8");
    };
    expect(emit()).toBe(emit());
  });

  it("batches large worklists and dispatches one agent per batch", async () => {
    const run = await makeRun({ scan: true, extraOpen: 17, verify: true });
    orchestrateRun(run, ENGINE);
    const src = readWf(run, "verify");
    const m = src.match(/const BATCHES = (\[.*?\])\n/s);
    expect(m).not.toBeNull();
    const batches = JSON.parse(m![1]!) as string[][];
    expect(batches.length).toBe(Math.ceil(20 / BATCH_SIZE));
    expect(batches.flat().length).toBe(20);
    expect(src).toContain("pipeline(BATCHES");
    expect(src).toContain("agentType: 'general-purpose'");
    expect(src).toContain("schema: SCHEMA");
  });

  it("small worklist (≤ SMALL_WORKLIST) → single agent + an eco notice", async () => {
    const run = await makeRun({ scan: true, verify: true });
    const res = orchestrateRun(run, ENGINE);
    const m = readWf(run, "verify").match(/const BATCHES = (\[.*?\])\n/s);
    expect((JSON.parse(m![1]!) as string[][]).length).toBe(1);
    expect(res.notices.some((n) => n.includes("--eco"))).toBe(true);
    expect(SMALL_WORKLIST).toBeLessThan(BATCH_SIZE);
  });

  it("an empty worklist is skipped with a notice, not emitted", async () => {
    // confirm "all" leaves zero OPEN candidates (adjudicate empty) but one
    // pending needs-human, so the verify worklist emitted afterwards is non-empty.
    const run = await makeRun({ scan: true, confirm: "all", verify: true });
    const res = orchestrateRun(run, ENGINE);
    expect(res.exitCode).toBe(0);
    expect(existsSync(wf(run, "adjudicate"))).toBe(false);
    expect(existsSync(wf(run, "verify"))).toBe(true);
    expect(res.notices.some((n) => n.includes("adjudicate") && n.includes("empty"))).toBe(true);
  });

  it("every contract('<role>') referenced by a workflow has its agents/<role>.md", async () => {
    const run = await fullRun();
    orchestrateRun(run, ENGINE);
    const agents = readdirSync(join(run, "orchestration", "agents")).map((f) => f.replace(/\.md$/, ""));
    for (const phase of PHASES) {
      const refs = [...readWf(run, phase).matchAll(/contract\('([a-z-]+)'/g)].map((m) => m[1]!);
      expect(refs.length).toBeGreaterThan(0);
      for (const r of refs) expect(agents).toContain(r);
    }
  });

  it("workflows return fragments and never contain a write step (--apply stays with the orchestrator)", async () => {
    const run = await fullRun();
    orchestrateRun(run, ENGINE);
    for (const phase of PHASES) {
      const src = readWf(run, phase);
      expect(src).toMatch(/^return \{/m);
      // --apply may appear only in comments (the orchestrator's next step), never as executed code.
      const code = src
        .split("\n")
        .filter((l) => !l.trim().startsWith("//"))
        .join("\n");
      expect(code).not.toContain("--apply");
    }
  });
});

describe("orchestrate — contracts & runbook", () => {
  it("every emitted contract carries the one-writer footer and returns structured output", async () => {
    const run = await fullRun();
    orchestrateRun(run, ENGINE);
    const dir = join(run, "orchestration", "agents");
    const files = readdirSync(dir);
    expect(files.sort()).toEqual(["analyzer.md", "hunter.md", "revalidator.md", "skeptic.md"]);
    for (const f of files) {
      const md = readFileSync(join(dir, f), "utf8");
      expect(md).toContain("Return, don't write");
      expect(md).toContain("The orchestrator is the sole writer");
      expect(md).toContain("orchestration/out/");
    }
  });

  it("analyzer + skeptic contracts encode the conservative verdict rules; revalidator + hunter their own", async () => {
    const run = await fullRun();
    orchestrateRun(run, ENGINE);
    const dir = join(run, "orchestration", "agents");
    const analyzer = readFileSync(join(dir, "analyzer.md"), "utf8");
    for (const v of ["`supported`", "`partial`", "`unsupported`", "`refuted`"]) expect(analyzer).toContain(v);
    expect(analyzer).toContain("dossier");
    expect(analyzer).toContain("exploitPath");
    expect(analyzer).toContain("needs-human");
    const skeptic = readFileSync(join(dir, "skeptic.md"), "utf8");
    for (const v of ["supported", "partial", "refuted", "unsupported"]) expect(skeptic).toContain(v);
    expect(skeptic).toMatch(/refute/i);
    expect(skeptic).toContain("needs-human");
    const reval = readFileSync(join(dir, "revalidator.md"), "utf8");
    for (const v of ["`still-valid`", "`fixed`", "`false-positive`", "`uncertain`"]) expect(reval).toContain(v);
    expect(reval).toContain("fixedIn");
    expect(reval).toContain("needs-human");
    const hunter = readFileSync(join(dir, "hunter.md"), "utf8");
    for (const k of ["authz", "IDOR", "business-logic", "Discovery"]) expect(hunter).toContain(k);
    expect(hunter).toMatch(/reject/i); // unresolvable citations are rejected at ingest
  });

  it("the runbook covers every phase with concrete paths and the phase status", async () => {
    const run = await fullRun();
    orchestrateRun(run, ENGINE);
    const rb = readFileSync(join(run, "orchestration", "RUNBOOK.md"), "utf8");
    for (const w of ["findings.json", "VERIFY.todo.json", "REVALIDATE.todo.json", "INVESTIGATE.todo.json"]) {
      expect(rb).toContain(join(run, w));
    }
    expect(rb).toContain(ENGINE);
    expect(rb).toContain("check --run");
    for (const role of ["analyzer.md", "skeptic.md", "revalidator.md", "hunter.md"]) expect(rb).toContain(role);
  });

  it("golden shape (paths normalized)", async () => {
    const run = await fullRun();
    orchestrateRun(run, ENGINE);
    expect(stable(readWf(run, "adjudicate"), run)).toMatchSnapshot("adjudicate.workflow.mjs");
    expect(stable(readFileSync(join(run, "orchestration", "agents", "skeptic.md"), "utf8"), run)).toMatchSnapshot("skeptic.md");
    expect(stable(readFileSync(join(run, "orchestration", "RUNBOOK.md"), "utf8"), run)).toMatchSnapshot("RUNBOOK.md");
  });
});

describe("orchestrate — eco mode & phase gating", () => {
  it("--eco emits RUNBOOK + contracts only, no workflow scripts", async () => {
    const run = await makeRun({ scan: true, verify: true });
    const res = orchestrateRun(run, ENGINE, { eco: true });
    expect(res.exitCode).toBe(0);
    expect(existsSync(join(run, "orchestration", "RUNBOOK.md"))).toBe(true);
    expect(existsSync(join(run, "orchestration", "agents", "analyzer.md"))).toBe(true);
    for (const phase of PHASES) expect(existsSync(wf(run, phase))).toBe(false);
  });

  it("--phase on a not-ready phase exits 2 and names the producing command", async () => {
    const run = await makeRun({ scan: true });
    const res = orchestrateRun(run, ENGINE, { phase: "revalidate" });
    expect(res.exitCode).toBe(2);
    expect(res.errors.some((e) => e.includes("revalidate --run"))).toBe(true);
    expect(existsSync(wf(run, "revalidate"))).toBe(false);
  });

  it("--phase restricts emission to that phase", async () => {
    const run = await makeRun({ scan: true, verify: true });
    const res = orchestrateRun(run, ENGINE, { phase: "verify" });
    expect(res.exitCode).toBe(0);
    expect(existsSync(wf(run, "verify"))).toBe(true);
    expect(existsSync(wf(run, "adjudicate"))).toBe(false);
  });

  it("an unknown phase exits 2 naming the valid ones", async () => {
    const run = await makeRun({ scan: true });
    const res = orchestrateRun(run, ENGINE, { phase: "nope" });
    expect(res.exitCode).toBe(2);
    expect(res.errors.some((e) => PHASES.every((p) => e.includes(p)))).toBe(true);
  });
});

describe("orchestrate — CLI wiring", () => {
  it("orchestrate without --run exits 2", async () => {
    expect(await engine("orchestrate")).toBe(2);
  });

  it("orchestrate --run <dir> --list exits 0 and prints {phases}; a full run emits and exits 0", async () => {
    const run = await makeRun({ scan: true, verify: true });
    let printed = "";
    const out = vi.spyOn(process.stdout, "write").mockImplementation((c: unknown) => {
      printed += String(c);
      return true;
    });
    const err = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    try {
      expect(await dispatch("orchestrate", parseArgs(["orchestrate", "--run", run, "--list"]))).toBe(0);
    } finally {
      out.mockRestore();
      err.mockRestore();
    }
    const listed = JSON.parse(printed) as { phases: { name: string }[] };
    expect(listed.phases.map((p) => p.name)).toEqual([...PHASES]);
    expect(await engine("orchestrate", "--run", run)).toBe(0);
    expect(existsSync(wf(run, "verify"))).toBe(true);
  });

  it("orchestrate --run <missing dir> exits 2", async () => {
    expect(await engine("orchestrate", "--run", join(tmpdir(), "usec-does-not-exist-xyz"))).toBe(2);
  });
});
