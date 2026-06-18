import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runRun } from "../src/commands/run.js";
import { parseArgs } from "../src/util.js";

const FIXTURE = join(import.meta.dirname, "fixtures", "vuln-express");

function capture(): { out: string[]; restore: () => void } {
  const out: string[] = [];
  const spy = vi.spyOn(process.stdout, "write").mockImplementation((chunk: any) => {
    out.push(String(chunk));
    return true;
  });
  return { out, restore: () => spy.mockRestore() };
}

describe("run command — stage selection & order", () => {
  let cap: ReturnType<typeof capture>;
  let errSpy: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    cap = capture();
    errSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  });
  afterEach(() => {
    cap.restore();
    errSpy.mockRestore();
  });

  it("non-powered: emits all stages in canonical order, zero external calls", () => {
    const run = mkdtempSync(join(tmpdir(), "ultrasec-runcmd-"));
    const code = runRun(parseArgs(["run", "--repo", FIXTURE, "--out", run, "--json"]));
    expect(code).toBe(0);
    const res = JSON.parse(cap.out.join(""));
    expect(res.externalCalls).toBe(0);
    expect(res.emitted.map((e: any) => e.stage)).toEqual(["context", "triage", "investigate", "verify", "revalidate", "narrative"]);
  });

  it("--stages keeps canonical order regardless of the order given", () => {
    const run = mkdtempSync(join(tmpdir(), "ultrasec-runcmd-"));
    const code = runRun(parseArgs(["run", "--repo", FIXTURE, "--out", run, "--stages", "verify,context", "--json"]));
    expect(code).toBe(0);
    const res = JSON.parse(cap.out.join(""));
    expect(res.emitted.map((e: any) => e.stage)).toEqual(["context", "verify"]); // canonical, not as-typed
  });

  it("rejects an unknown stage", () => {
    const run = mkdtempSync(join(tmpdir(), "ultrasec-runcmd-"));
    expect(runRun(parseArgs(["run", "--repo", FIXTURE, "--out", run, "--stages", "bogus"]))).toBe(2);
  });

  it("--no-scan with no prior dossier is an error", () => {
    const run = mkdtempSync(join(tmpdir(), "ultrasec-runcmd-"));
    expect(runRun(parseArgs(["run", "--repo", FIXTURE, "--out", run, "--no-scan"]))).toBe(2);
  });
});
