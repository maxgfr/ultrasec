import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runClean, dockerImages } from "../src/commands/clean.js";
import { parseArgs } from "../src/util.js";
import { ADAPTERS } from "../src/tools/index.js";

const DELIVERABLES = ["SUMMARY.md", "REPORT.md", "index.html", "findings.json"];
const INTERMEDIATES = ["manifest.json", "graph.json", "DOSSIER.md", "VERIFY.todo.json", "NARRATIVE.json"];

// A fully-rendered run: deliverables + intermediate scan artifacts + a cache subdir.
function makeRun(files: string[] = [...DELIVERABLES, ...INTERMEDIATES]): string {
  const dir = mkdtempSync(join(tmpdir(), "ultrasec-clean-"));
  const run = join(dir, ".ultrasec");
  mkdirSync(run, { recursive: true });
  for (const f of files) writeFileSync(join(run, f), f.endsWith(".json") ? "{}" : "x");
  return run;
}
const has = (run: string, f: string) => existsSync(join(run, f));

describe("clean — output removal", () => {
  // Eval P1.5: `clean` used to rmSync the WHOLE run dir, silently destroying the
  // rendered REPORT/SUMMARY/index.html a user just produced. Default now preserves
  // the deliverables and removes only the intermediate scan artifacts.
  it("preserves the rendered deliverables and removes the intermediates by default", () => {
    const run = makeRun();
    runClean(parseArgs(["clean", "--run", run]));
    expect(existsSync(run)).toBe(true);
    for (const d of DELIVERABLES) expect(has(run, d), `${d} kept`).toBe(true);
    for (const i of INTERMEDIATES) expect(has(run, i), `${i} removed`).toBe(false);
  });

  it("--all removes the entire run dir including deliverables", () => {
    const run = makeRun();
    runClean(parseArgs(["clean", "--run", run, "--all"]));
    expect(existsSync(run)).toBe(false);
  });

  it("prunes the dir when there are no deliverables to keep", () => {
    const run = makeRun(INTERMEDIATES); // never rendered
    runClean(parseArgs(["clean", "--run", run]));
    expect(existsSync(run)).toBe(false);
  });

  it("--dry-run removes nothing", () => {
    const run = makeRun();
    runClean(parseArgs(["clean", "--run", run, "--dry-run"]));
    for (const f of [...DELIVERABLES, ...INTERMEDIATES]) expect(has(run, f)).toBe(true);
  });

  it("--keep-output leaves the whole dossier untouched", () => {
    const run = makeRun();
    runClean(parseArgs(["clean", "--run", run, "--keep-output"]));
    for (const f of [...DELIVERABLES, ...INTERMEDIATES]) expect(has(run, f)).toBe(true);
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
