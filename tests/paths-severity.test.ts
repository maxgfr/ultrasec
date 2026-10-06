import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runPaths } from "../src/commands/paths.js";
import { captureOutput, parseArgs } from "../src/util.js";

// `paths --severity high` on a real audit listed 83 chains and silently left out
// the only critical one: the flag was an equality filter, while `check` spells a
// threshold `--min-severity`. Both now exist on `paths`, with the same meaning
// they have everywhere else, and an exact filter says what it hid above it.

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function run(): string {
  const dir = mkdtempSync(join(tmpdir(), "ultrasec-paths-"));
  dirs.push(dir);
  const chain = (id: string, severity: string) => ({
    id,
    category: "taint",
    title: `t-${id}`,
    severity,
    confidence: "medium",
    message: "m",
    tool: "ultrasec",
    status: "open",
    path: [{ file: "a.js", line: 1 }],
  });
  writeFileSync(join(dir, "findings.json"), JSON.stringify([chain("crit1", "critical"), chain("high1", "high"), chain("med1", "medium")]));
  writeFileSync(join(dir, "manifest.json"), "{}");
  writeFileSync(join(dir, "graph.json"), "{}");
  return dir;
}

async function ids(argv: string[]): Promise<{ code: number; ids: string[]; text: string }> {
  const { result, stdout, stderr } = await captureOutput(() => runPaths(parseArgs(["paths", ...argv])));
  const rows = stdout.split("\n").filter((l) => /^\w+ {2}/.test(l));
  return { code: result, ids: rows.map((l) => l.split(/\s+/)[0]!), text: `${stdout}\n${stderr}` };
}

describe("paths severity filters", () => {
  it("--min-severity high keeps high AND critical", async () => {
    const r = await ids(["--run", run(), "--min-severity", "high"]);
    expect(r.ids.sort()).toEqual(["crit1", "high1"]);
  });

  it("--severity stays an exact filter, and says what it left out above it", async () => {
    const r = await ids(["--run", run(), "--severity", "high"]);
    expect(r.ids).toEqual(["high1"]);
    expect(r.text).toMatch(/1 critical chain\(s\) above this severity.*--min-severity high/);
  });

  it("refuses an unknown severity instead of matching nothing", async () => {
    expect((await ids(["--run", run(), "--min-severity", "hgih"])).code).toBe(2);
    expect((await ids(["--run", run(), "--severity", "hgih"])).code).toBe(2);
  });

  it("--json honours the floor too", async () => {
    const { stdout } = await captureOutput(() => runPaths(parseArgs(["paths", "--run", run(), "--min-severity", "high", "--json"])));
    expect((JSON.parse(stdout) as { id: string }[]).map((f) => f.id).sort()).toEqual(["crit1", "high1"]);
  });
});
