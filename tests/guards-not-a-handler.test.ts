import { afterEach, describe, expect, it, vi } from "vitest";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { runGuards } from "../src/commands/guards.js";
import { runScan } from "../src/commands/scan.js";
import { NOT_A_HANDLER, parseGuardVerdicts, renderGuardsMd, type GuardRow } from "../src/guards.js";
import { parseArgs } from "../src/util.js";

// The matrix is built from request-data reads, so it also lists code that only
// mentions them. On a Next.js + Express monorepo 26 of 53 rows were a zod body
// schema, a barrel re-export, an outbound client, a `config` object or a React
// component — and with `intentionally-public` as the only way to answer them,
// the report claimed 32 deliberately public routes where there were 6.

const dirs: string[] = [];
const tmp = (p: string) => {
  const d = mkdtempSync(join(tmpdir(), p));
  dirs.push(d);
  return d;
};
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  vi.restoreAllMocks();
});

describe("not-a-handler verdict", () => {
  it("is accepted by both lenses", () => {
    for (const lens of ["auth", "throttle"] as const) {
      const parsed = parseGuardVerdicts(JSON.stringify([{ id: "a1", verdict: NOT_A_HANDLER, note: "zod schema" }]), lens);
      expect(parsed.rows).toEqual([{ id: "a1", verdict: NOT_A_HANDLER, note: "zod schema" }]);
      expect(parsed.dropped).toEqual([]);
    }
  });

  it("is offered in both briefs", () => {
    const rows: GuardRow[] = [];
    expect(renderGuardsMd(rows)).toContain(`\`${NOT_A_HANDLER}\``);
    expect(renderGuardsMd(rows, undefined, "throttle")).toContain(`\`${NOT_A_HANDLER}\``);
  });

  it("drops the row: no finding, not counted as public", async () => {
    const repo = tmp("ultrasec-nah-repo-");
    cpSync(resolve("tests/fixtures/vuln-express"), repo, { recursive: true });
    const run = tmp("ultrasec-nah-run-");
    vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    expect(await runScan(parseArgs(["scan", "--repo", repo, "--out", run, "--offline", "--no-tools", "--quiet"]))).toBe(0);
    expect(runGuards(parseArgs(["guards", "--run", run]))).toBe(0);
    const rows = JSON.parse(readFileSync(join(run, "GUARDS.todo.json"), "utf8")) as GuardRow[];
    expect(rows.length).toBeGreaterThan(0);
    const findings = () => (JSON.parse(readFileSync(join(run, "findings.json"), "utf8")) as unknown[]).length;
    const before = findings();

    const apply = join(run, "GUARDS.json");
    writeFileSync(apply, JSON.stringify(rows.map((r) => ({ id: r.id, verdict: NOT_A_HANDLER, note: "not a route" }))));
    const out = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    expect(runGuards(parseArgs(["guards", "--run", run, "--apply", apply, "--strict"]))).toBe(0);
    const printed = out.mock.calls.map((c) => String(c[0])).join("");
    expect(printed).toContain(`0 intentionally-public · ${rows.length} ${NOT_A_HANDLER} (dropped)`);
    expect(printed).toContain("0 unguarded handler(s) filed as findings");
    expect(findings()).toBe(before);
  });

  it("guards takes --json, on emit and on apply", async () => {
    const repo = tmp("ultrasec-gjson-repo-");
    cpSync(resolve("tests/fixtures/vuln-express"), repo, { recursive: true });
    const run = tmp("ultrasec-gjson-run-");
    vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const out = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    expect(await runScan(parseArgs(["scan", "--repo", repo, "--out", run, "--offline", "--no-tools", "--quiet"]))).toBe(0);
    out.mockClear();
    expect(runGuards(parseArgs(["guards", "--run", run, "--json"]))).toBe(0);
    const emit = JSON.parse(out.mock.calls.map((c) => String(c[0])).join("")) as { todo: string; items: number; counts: { handlers: number } };
    expect(emit.todo).toBe(join(run, "GUARDS.todo.json"));
    expect(emit.items).toBe(emit.counts.handlers);
    const rows = JSON.parse(readFileSync(emit.todo, "utf8")) as GuardRow[];
    const apply = join(run, "GUARDS.json");
    writeFileSync(apply, JSON.stringify([...rows.map((r) => ({ id: r.id, verdict: NOT_A_HANDLER })), { id: "nope", verdict: NOT_A_HANDLER }]));
    out.mockClear();
    expect(runGuards(parseArgs(["guards", "--run", run, "--apply", apply, "--json"]))).toBe(0);
    const res = JSON.parse(out.mock.calls.map((c) => String(c[0])).join("")) as { unknown: string[]; [k: string]: unknown };
    expect(res.unknown).toEqual(["nope"]);
    expect(res[NOT_A_HANDLER]).toBe(rows.length);
  });
});
