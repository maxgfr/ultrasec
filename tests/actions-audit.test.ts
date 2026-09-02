import { describe, it, expect } from "vitest";
import { join } from "node:path";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { auditAgenticWorkflows, VECTORS } from "../src/actions.js";

const FIXTURE = join(import.meta.dirname, "fixtures", "agentic-ci");

describe("agentic CI audit", () => {
  const findings = auditAgenticWorkflows(FIXTURE);
  const vec = (id: string) => findings.filter((f) => f.title.includes(`vector ${id}:`));

  it("catches the env-var intermediary — the shape surface review misses", () => {
    // The prompt field contains no `${{ }}` at all; the attacker-controlled value
    // arrives through `env:` and is interpolated by the shell. This is the one
    // that matters: a reviewer reading the prompt sees nothing wrong.
    const a = vec("A");
    expect(a.length).toBe(1);
    expect(a[0]!.sink?.file).toBe(".github/workflows/vulnerable.yml");
    expect(a[0]!.severity).toBe("critical");
    expect(a[0]!.message).toMatch(/ISSUE_BODY/);
  });

  it("catches direct interpolation into a prompt", () => {
    expect(vec("B")).toHaveLength(1);
  });

  it("catches pull_request_target checking out the PR head", () => {
    const d = vec("D");
    expect(d).toHaveLength(1);
    expect(d[0]!.severity).toBe("critical");
  });

  it("catches execution of model output", () => {
    expect(vec("G")).toHaveLength(1);
  });

  it("resolves the step id when `id:` follows `uses:` — the ordering everybody writes", () => {
    // A forward-only scan that remembers the last id seen finds nothing here, and
    // can carry an id across a step boundary onto the wrong action. This test
    // used to pass by exactly that accident.
    const dir = mkdtempSync(join(tmpdir(), "ultrasec-actions-"));
    mkdirSync(join(dir, ".github", "workflows"), { recursive: true });
    writeFileSync(
      join(dir, ".github", "workflows", "w.yml"),
      [
        "name: x",
        "on: [issues]",
        "jobs:",
        "  j:",
        "    steps:",
        "      - uses: anthropics/claude-code-action@v1",
        "        id: ai",
        "        with:",
        '          prompt: "hi"',
        '      - run: eval "${{ steps.ai.outputs.result }}"',
        "",
      ].join("\n"),
    );
    const f = auditAgenticWorkflows(dir);
    expect(f.filter((x) => x.title.includes("vector G:"))).toHaveLength(1);
  });

  it("does not attribute one step's id to another step's action", () => {
    // `build` belongs to a plain step; executing ITS output is not model output.
    const dir = mkdtempSync(join(tmpdir(), "ultrasec-actions-"));
    mkdirSync(join(dir, ".github", "workflows"), { recursive: true });
    writeFileSync(
      join(dir, ".github", "workflows", "w.yml"),
      [
        "name: x",
        "on: [push]",
        "jobs:",
        "  j:",
        "    steps:",
        "      - run: make",
        "        id: build",
        "      - uses: anthropics/claude-code-action@v1",
        "        with:",
        '          prompt: "hi"',
        '      - run: eval "${{ steps.build.outputs.x }}"',
        "",
      ].join("\n"),
    );
    expect(auditAgenticWorkflows(dir).filter((x) => x.title.includes("vector G:"))).toEqual([]);
  });

  it("catches a disabled sandbox", () => {
    expect(vec("H").length).toBeGreaterThan(0);
  });

  it("catches a wildcard user allow-list", () => {
    expect(vec("I")).toHaveLength(1);
  });

  it("leaves the safe workflow alone", () => {
    // Constant prompt, no event data, a scoped tool allow-list: nothing to report.
    const onSafe = findings.filter((f) => (f.sink?.file ?? "").endsWith("safe.yml") || (f.locations ?? []).some((l) => l.file.endsWith("safe.yml")));
    expect(onSafe).toEqual([]);
  });

  it("cites a resolvable [file:line] for every finding", () => {
    for (const f of findings) {
      expect(f.sink?.file, `${f.title} must cite a file`).toBeTruthy();
      expect(f.sink!.line).toBeGreaterThan(0);
    }
  });

  it("files the agent vectors under CWE-1427 (prompt injection), the supply-chain ones under their own CWE", () => {
    for (const f of findings) {
      const v = /vector ([A-Z]):/.exec(f.title)![1]!;
      if (v === "J") expect(f.cwe).toBe("CWE-829");
      else if (v === "K") expect(f.cwe).toBe("CWE-250");
      else expect(f.cwe, f.title).toBe("CWE-1427");
    }
  });

  it("J: flags every action pinned to a tag or branch, never a full commit SHA, and never a local/docker action", () => {
    const j = vec("J").filter((f) => f.sink?.file.endsWith("unpinned.yml"));
    // checkout@v4, setup-node@main, ref-less action, claude-code-action@v1 —
    // and NOT the SHA-pinned one, the `./local` one or the `docker://` one.
    expect(j.map((f) => f.sink!.line).sort((a, b) => a - b)).toEqual([12, 13, 14, 20]);
    expect(j.every((f) => f.severity === "medium")).toBe(true);
    expect(vec("J").filter((f) => f.sink?.file === ".github/workflows/pinned.yml")).toEqual([]);
  });

  it("K: flags a workflow with no permissions block, or with write-all, on a citable line", () => {
    const unpinned = vec("K").filter((f) => f.sink?.file.endsWith("unpinned.yml"));
    expect(unpinned).toHaveLength(1);
    expect(unpinned[0]!.severity).toBe("high");
    expect(unpinned[0]!.message).toMatch(/write-all/);
    expect(vec("K").filter((f) => f.sink?.file === ".github/workflows/pinned.yml")).toEqual([]);
    // The vulnerable fixture has no permissions block at all: cited on `on:`.
    const vulnerable = vec("K").filter((f) => f.sink?.file.endsWith("vulnerable.yml"));
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]!.message).toMatch(/no permissions: block/);
  });

  it("reports nothing on a repo with no workflows", () => {
    expect(auditAgenticWorkflows(join(import.meta.dirname, "fixtures", "vuln-express"))).toEqual([]);
  });

  it("keeps the vector table and the engine in one place", () => {
    for (const v of Object.values(VECTORS)) {
      expect(v.note.length).toBeGreaterThan(40);
      expect(v.title.length).toBeGreaterThan(10);
    }
  });
});
