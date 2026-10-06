import { afterEach, describe, expect, it } from "vitest";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanRepo } from "../src/scan.js";
import { buildGuardMatrix } from "../src/guards.js";

// The guard matrix on a real Next.js app: 358 rows, 187 of them from test files
// (a test that builds a Request is not an entry point), and every route written
// as `export const GET = withX(opts, handler)` reported TWICE — the exported
// wrapper and the handler it wraps — so one missing check became two findings,
// and a guard inside the handler left the wrapper row "unguarded".

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
function repo(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "ultrasec-guards-"));
  dirs.push(dir);
  for (const [rel, body] of Object.entries(files)) {
    mkdirSync(join(dir, rel, ".."), { recursive: true });
    writeFileSync(join(dir, rel), body);
  }
  return dir;
}

const WRAPPED_OPEN = `import { withAudit } from "~/audit";

export const GET = withAudit(
  {
    action: "report.download",
    describe: (request) => ({ year: new URL(request.url).searchParams.get("year") }),
  },
  downloadReport,
);

async function downloadReport(request: Request): Promise<Response> {
  const year = new URL(request.url).searchParams.get("year");
  return Response.json({ year });
}
`;

const WRAPPED_GUARDED = `import { withAudit } from "~/audit";

export const POST = withAudit({ action: "sync.run" }, runSync);

async function runSync(request: Request): Promise<Response> {
  const header = request.headers.get("authorization");
  if (!(await requireAuth(header))) return new Response(null, { status: 401 });
  return Response.json({ ok: true });
}
`;

const A_TEST = `import { GET } from "../route";

it("downloads", async () => {
  const res = await GET(new Request("http://x/api/report?year=2024"));
  expect(new URL(res.url).searchParams.get("year")).toBe("2024");
});
`;

describe("guard matrix noise", () => {
  it("one row per wrapped route, crediting the wrapped handler's guard", () => {
    const r = repo({ "app/api/report/route.ts": WRAPPED_OPEN, "app/api/sync/route.ts": WRAPPED_GUARDED });
    const rows = buildGuardMatrix(scanRepo(r));
    const report = rows.filter((x) => x.file === "app/api/report/route.ts");
    const sync = rows.filter((x) => x.file === "app/api/sync/route.ts");
    expect(report).toHaveLength(1);
    expect(report[0]!.state).toBe("unguarded");
    expect(sync).toHaveLength(1);
    expect(sync[0]!.state).toBe("guarded");
    expect(sync[0]!.handler).toBe("POST");
  });

  it("skips test files unless the run kept tests", () => {
    const r = repo({ "app/api/report/route.ts": WRAPPED_OPEN, "app/api/report/__tests__/route.test.ts": A_TEST });
    expect(buildGuardMatrix(scanRepo(r)).map((x) => x.file)).toEqual(["app/api/report/route.ts"]);
    expect(buildGuardMatrix(scanRepo(r), "auth", [], { includeTests: true }).map((x) => x.file)).toContain("app/api/report/__tests__/route.test.ts");
  });
});
