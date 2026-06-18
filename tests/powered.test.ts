import { describe, it, expect } from "vitest";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildAgentArgv, resolveTemplate, CliAgentRunner, type AgentRunner, type AgentTask, type SpawnFn } from "../src/powered/agent.js";
import { runPipeline, reconcileCrossCheck, ALL_STAGES, type StageName } from "../src/powered/pipeline.js";
import { loadDossier } from "../src/store.js";
import type { Finding } from "../src/types.js";

const FIXTURE = join(import.meta.dirname, "fixtures", "vuln-express");
const tmpRun = () => mkdtempSync(join(tmpdir(), "ultrasec-powered-"));

describe("agent argv hardening", () => {
  it("built-in claude/codex pass the instruction as a SINGLE argv element (no shell)", () => {
    const instr = "audit; rm -rf / `whoami` $(touch x) && echo pwned";
    const claude = buildAgentArgv("claude", instr, "/run");
    expect(claude).toEqual(["claude", "-p", instr]); // metacharacters inert — one element
    expect(buildAgentArgv("codex", instr, "/run")).toEqual(["codex", "exec", instr]);
  });

  it("a generic template substitutes {prompt}/{run} per token", () => {
    expect(buildAgentArgv("mytool exec {prompt} --cwd {run}", "DO IT", "/r")).toEqual(["mytool", "exec", "DO IT", "--cwd", "/r"]);
  });

  it("rejects an empty template", () => {
    expect(() => resolveTemplate("   ")).toThrow();
  });
});

describe("CliAgentRunner — drives an argv-only CLI, verifies output", () => {
  const task = (outPath: string): AgentTask => ({ stage: "verify", run: tmpRun(), worklist: "/run/VERIFY.md", outPath, instruction: "fill it" });

  it("succeeds only when the CLI exits 0 AND writes a non-empty output file", () => {
    const out = join(tmpRun(), "verdicts.json");
    let seen: { cmd: string; args: string[] } | undefined;
    const spawn: SpawnFn = (cmd, args) => {
      seen = { cmd, args };
      writeFileSync(out, "[]"); // the "agent" produced output
      return { status: 0, stderr: "" };
    };
    const r = new CliAgentRunner("claude", spawn).fill(task(out));
    expect(r.ok).toBe(true);
    expect(seen).toEqual({ cmd: "claude", args: ["-p", "fill it"] }); // argv-only
  });

  it("fails when the CLI exits non-zero", () => {
    const out = join(tmpRun(), "verdicts.json");
    const spawn: SpawnFn = () => ({ status: 1, stderr: "boom" });
    expect(new CliAgentRunner("claude", spawn).fill(task(out)).ok).toBe(false);
  });

  it("fails when the CLI exits 0 but writes nothing (no hallucinated success)", () => {
    const out = join(tmpRun(), "missing.json");
    const spawn: SpawnFn = () => ({ status: 0, stderr: "" });
    expect(new CliAgentRunner("claude", spawn).fill(task(out)).ok).toBe(false);
  });
});

describe("reconcileCrossCheck", () => {
  const f = (id: string, severity: Finding["severity"], status: Finding["status"]): Finding => ({
    id, category: "taint", title: id, severity, confidence: "high", message: "m", tool: "ultrasec", status, sink: { file: "a", line: 1 },
  });

  it("escalates a HIGH/CRITICAL disagreement to needs-human (never downgrades)", () => {
    const primary = [f("a", "high", "confirmed"), f("b", "low", "confirmed")];
    const cross = [f("a", "high", "dismissed"), f("b", "low", "dismissed")];
    const { findings, escalated } = reconcileCrossCheck(primary, cross);
    expect(findings.find((x) => x.id === "a")!.status).toBe("needs-human"); // high disagreement
    expect(findings.find((x) => x.id === "b")!.status).toBe("confirmed"); // low disagreement left alone
    expect(escalated).toEqual(["a"]);
  });

  it("leaves agreeing high findings unchanged", () => {
    const primary = [f("a", "high", "confirmed")];
    const cross = [f("a", "high", "confirmed")];
    expect(reconcileCrossCheck(primary, cross).escalated).toEqual([]);
  });
});

// A mock agent that fills each worklist with a canned, valid output.
class MockRunner implements AgentRunner {
  calls: string[] = [];
  constructor(private verifyVerdict: "supported" | "refuted" = "supported") {}
  fill(task: AgentTask) {
    this.calls.push(task.stage);
    const stage = task.stage.replace(/:cross$/, "");
    if (stage === "context") writeFileSync(task.outPath, "# Context\nAuth via JWT on /admin.\n");
    else if (stage === "triage") writeFileSync(task.outPath, "[]");
    else if (stage === "investigate") writeFileSync(task.outPath, "[]");
    else if (stage === "narrative") writeFileSync(task.outPath, "{}");
    else if (stage === "verify") {
      const items = JSON.parse(readFileSync(join(task.run, "VERIFY.todo.json"), "utf8")) as { id: string }[];
      writeFileSync(task.outPath, JSON.stringify(items.map((i) => ({ id: i.id, verdict: this.verifyVerdict }))));
    } else if (stage === "revalidate") {
      const items = JSON.parse(readFileSync(join(task.run, "REVALIDATE.todo.json"), "utf8")) as { id: string }[];
      writeFileSync(task.outPath, JSON.stringify(items.map((i) => ({ id: i.id, verdict: "still-valid" }))));
    }
    return { ok: true };
  }
}

// A runner that must NEVER be invoked (asserts zero external calls).
class ExplodingRunner implements AgentRunner {
  fill(): { ok: boolean } {
    throw new Error("agent must not be invoked in non-powered mode");
  }
}

describe("runPipeline — non-powered (keyless default)", () => {
  it("emits every stage worklist and makes ZERO external calls", () => {
    const run = tmpRun();
    const res = runPipeline({ repo: FIXTURE, run, powered: false, stages: [...ALL_STAGES] as StageName[], runner: new ExplodingRunner() });
    expect(res.externalCalls).toBe(0);
    // emit-only: no fill:/apply: actions, but a worklist per stage + check + render
    expect(res.actions.filter((a) => a.startsWith("fill:"))).toHaveLength(0);
    expect(res.actions.filter((a) => a.startsWith("apply:"))).toHaveLength(0);
    expect(res.emitted.map((e) => e.stage)).toEqual([...ALL_STAGES]);
    expect(res.actions[0]).toBe("scan");
    expect(res.actions.at(-1)).toBe("render");
  });
});

describe("runPipeline — powered", () => {
  it("runs each stage in canonical emit→fill→apply order", () => {
    const run = tmpRun();
    const mock = new MockRunner();
    const res = runPipeline({ repo: FIXTURE, run, powered: true, stages: [...ALL_STAGES] as StageName[], runner: mock });
    // context + narrative have no apply; the rest do
    expect(res.actions).toEqual([
      "scan",
      "emit:context", "fill:context",
      "emit:triage", "fill:triage", "apply:triage",
      "emit:investigate", "fill:investigate", "apply:investigate",
      "emit:verify", "fill:verify", "apply:verify",
      "emit:revalidate", "fill:revalidate", "apply:revalidate",
      "emit:narrative", "fill:narrative",
      "check", "render",
    ]);
    expect(mock.calls).toContain("verify");
    expect(res.externalCalls).toBe(6); // one per stage
  });

  it("cross-check: a high/critical disagreement on verify escalates to needs-human", () => {
    const run = tmpRun();
    const res = runPipeline({
      repo: FIXTURE,
      run,
      powered: true,
      stages: ["verify"],
      runner: new MockRunner("supported"), // primary → confirmed
      crossRunner: new MockRunner("refuted"), // cross → dismissed
    });
    expect(res.actions).toContain("crosscheck:verify");
    expect(res.externalCalls).toBe(2); // primary + cross
    const high = loadDossier(run).findings.filter((f) => (f.severity === "high" || f.severity === "critical"));
    expect(high.length).toBeGreaterThan(0);
    expect(high.every((f) => f.status === "needs-human")).toBe(true); // escalated
    expect(res.escalated.length).toBeGreaterThan(0);
  });
});
