import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runClean, dockerImages } from "../src/commands/clean.js";
import { parseArgs } from "../src/util.js";
import { ADAPTERS } from "../src/tools/index.js";

function makeRun(): string {
  const dir = mkdtempSync(join(tmpdir(), "ultrasec-clean-"));
  const run = join(dir, ".ultrasec");
  mkdirSync(run, { recursive: true });
  writeFileSync(join(run, "findings.json"), "[]");
  return run;
}

describe("clean — output removal", () => {
  it("removes the audit dossier dir", () => {
    const run = makeRun();
    expect(existsSync(run)).toBe(true);
    runClean(parseArgs(["clean", "--run", run]));
    expect(existsSync(run)).toBe(false);
  });

  it("--dry-run removes nothing", () => {
    const run = makeRun();
    runClean(parseArgs(["clean", "--run", run, "--dry-run"]));
    expect(existsSync(run)).toBe(true);
  });

  it("--keep-output leaves the dossier", () => {
    const run = makeRun();
    runClean(parseArgs(["clean", "--run", run, "--keep-output"]));
    expect(existsSync(run)).toBe(true);
  });
});

describe("clean — docker artifacts list", () => {
  it("targets every pinned scanner image plus the toolbox image", () => {
    const imgs = dockerImages();
    expect(imgs).toContain("ultrasec-toolbox");
    for (const a of ADAPTERS) if (a.dockerImage) expect(imgs).toContain(a.dockerImage);
    // de-duplicated
    expect(new Set(imgs).size).toBe(imgs.length);
  });
});
