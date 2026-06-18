import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, rmSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runImport } from "../src/commands/import.js";
import { parseArgs } from "../src/util.js";

const sample = JSON.stringify([
  {
    title: "SQLi",
    description: "CWE-89",
    severity: "HIGH",
    labels: [],
    metadata: { filePath: "src/db.ts", lineNumbers: [3], vulnSlug: "sql-injection", confidence: "high", owners: {} },
  },
]);

describe("runImport (deepsec → dossier)", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "ultrasec-import-"));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("ingests a deepsec export into a fresh run dossier (offline)", async () => {
    const file = join(dir, "deepsec.json");
    writeFileSync(file, sample);
    const run = join(dir, ".ultrasec");
    const code = await runImport(parseArgs(["import", file, "--run", run, "--offline"]));
    expect(code).toBe(0);
    expect(existsSync(join(run, "findings.json"))).toBe(true);
    const findings = JSON.parse(readFileSync(join(run, "findings.json"), "utf8"));
    expect(findings).toHaveLength(1);
    expect(findings[0].tool).toBe("deepsec");
    expect(findings[0].category).toBe("sast");
    expect(findings[0].sink).toEqual({ file: "src/db.ts", line: 3 });
    expect(findings[0].status).toBe("open");
    const manifest = JSON.parse(readFileSync(join(run, "manifest.json"), "utf8"));
    expect(manifest.toolsRun).toContain("deepsec");
  });

  it("returns non-zero when the file has no parseable findings", async () => {
    const file = join(dir, "empty.json");
    writeFileSync(file, "[]");
    const code = await runImport(parseArgs(["import", file, "--run", join(dir, ".ultrasec"), "--offline"]));
    expect(code).toBe(1);
  });

  it("returns non-zero when the file is missing", async () => {
    const code = await runImport(parseArgs(["import", join(dir, "nope.json"), "--run", join(dir, ".ultrasec")]));
    expect(code).toBe(2);
  });
});
