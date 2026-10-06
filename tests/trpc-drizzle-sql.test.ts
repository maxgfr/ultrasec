import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { findSinks } from "../src/catalog.js";
import { langForFile } from "../src/lang.js";
import { scanRepo } from "../src/scan.js";
import { buildGraph } from "../src/graph.js";
import { enumerateTaint } from "../src/taint.js";

// On a real tRPC + Drizzle app, 53 "SQL injection" candidates: 31 were tRPC
// procedure DECLARATIONS (`getById: adminProcedure.input(…).query(async …)`,
// where `.query(` registers a handler) and the rest Drizzle `sql` tagged
// templates, which bind every interpolation as a parameter. The one `sql.raw`
// was the only shape that can inject. The fixture is synthetic.

const FIXTURE = join(import.meta.dirname, "fixtures", "trpc-drizzle");
const js = langForFile("x.ts")!;
const DRIZZLE = [{ spec: "drizzle-orm" }];
const sqlHits = (calls: { callee: string; receiver?: string; line: number }[], src: string, imports = DRIZZLE) =>
  findSinks(js, calls, undefined, imports, undefined, src.split("\n")).filter((h) => h.kind === "sql");

describe("SQL sinks in a tRPC + Drizzle codebase", () => {
  it("a tRPC procedure's `.query(` taking a callback is not a SQL sink", () => {
    const src = "  byId: memberProcedure\n    .input(schema)\n    .query(async ({ ctx, input }) => {\n";
    expect(sqlHits([{ callee: "query", line: 1 }], src)).toEqual([]);
    expect(sqlHits([{ callee: "query", line: 1 }], "  list: publicProcedure.query(({ ctx }) => ctx.db.select())\n")).toEqual([]);
  });

  it("an `execute(sql`…`)` Drizzle template — generic type argument included — is parameterized", () => {
    const multi = "const rows = await ctx.db.execute<{\n  total: number;\n}>(\n  sql`SELECT ${input.year}`,\n);\n";
    expect(sqlHits([{ callee: "execute", line: 1 }], multi)).toEqual([]);
    expect(sqlHits([{ callee: "execute", receiver: "tx", line: 1 }], "await tx.execute(\n  sql`SELECT ${id}`,\n);\n")).toEqual([]);
  });

  it("the same template stays a candidate when the file does not import a parameterizing `sql` tag", () => {
    const src = "await db.execute(sql`SELECT ${id}`);\n";
    expect(sqlHits([{ callee: "execute", receiver: "db", line: 1 }], src, [{ spec: "./my-sql-helper" }])).toHaveLength(1);
  });

  it("a string-built query and `sql.raw(x)` stay sinks", () => {
    expect(sqlHits([{ callee: "query", receiver: "pool", line: 1 }], "pool.query(`SELECT * FROM t WHERE id = ${id}`);\n")).toHaveLength(1);
    expect(sqlHits([{ callee: "query", receiver: "pool", line: 1 }], 'pool.query("SELECT 1 WHERE a = " + a);\n')).toHaveLength(1);
    expect(sqlHits([{ callee: "raw", receiver: "sql", line: 1 }], "sql`ORDER BY ${sql.raw(input.column)}`;\n")).toHaveLength(1);
  });

  it("end to end: only the sql.raw flow survives", () => {
    const scan = scanRepo(FIXTURE);
    const sql = enumerateTaint(scan, buildGraph(scan), { maxDepth: 8, maxCandidates: 1000 }).findings.filter((f) => f.cwe === "CWE-89");
    const at = sql.map((f) => `${f.sink!.file}:${f.sink!.line}`);
    const rawLine =
      readFileSync(join(FIXTURE, "server", "report.ts"), "utf8")
        .split("\n")
        .findIndex((l) => l.includes("sql.raw(")) + 1;
    expect(at).toContain(`server/report.ts:${rawLine}`);
    expect(at.filter((a) => a.startsWith("server/router.ts"))).toEqual([]);
  });
});
