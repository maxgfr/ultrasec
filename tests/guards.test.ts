import { describe, it, expect } from "vitest";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanRepo } from "../src/scan.js";
import { buildGuardMatrix, guardDiscovery, guardTotals, renderGuardsMd, type GuardRow } from "../src/guards.js";

// The entry-point × guard matrix — the vulnerability that is an ABSENCE.
//
// Motivated by a real audit: four HTTP routes read `session_variables` from the
// request body and called Hasura with the admin secret, and the engine reported
// an unrelated candidate on a neighbouring line. Entry points and auth markers
// were both being computed; nothing crossed them. These tests pin the crossing.

function repoWith(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "ultrasec-guards-"));
  for (const [rel, body] of Object.entries(files)) {
    const abs = join(dir, rel);
    mkdirSync(join(abs, ".."), { recursive: true });
    writeFileSync(abs, body);
  }
  return dir;
}

const matrixOf = (files: Record<string, string>): GuardRow[] => buildGuardMatrix(scanRepo(repoWith(files)));
const row = (rows: GuardRow[], handler: string) => rows.find((r) => r.handler === handler);

describe("guard matrix", () => {
  const rows = matrixOf({
    // The shape that cost the audit: reads the request, checks nothing.
    "src/publish.js": `export function publish(req, res) {
  const id = req.body.id;
  const src = req.body.source;
  res.end(run(id, src));
}
`,
    // The same shape with a real check in it.
    "src/admin.js": `export function admin(req, res) {
  if (!requireAuth(req)) return res.status(401).end();
  const id = req.body.id;
  res.end(id);
}
`,
    // Two handlers in ONE file: the guard belongs to the first only. Without a
    // per-handler scope, the second would be credited with the first's check.
    "src/both.js": `export function guardedOne(req, res) {
  verifyToken(req.headers.authorization);
  res.end(req.body.a);
}

export function openOne(req, res) {
  res.end(req.body.b);
}
`,
    // No request read at all — not an authorization question, not a row.
    "src/util.js": `export function slugify(s) {
  return String(s).toLowerCase();
}
`,
  });

  it("flags a handler that reads the request and checks nothing", () => {
    const r = row(rows, "publish");
    expect(r?.state).toBe("unguarded");
    expect(r?.kinds).toContain("http");
    // Three reads (`req.body.id`, `req.body.source`, and the `req` parameter
    // itself) collapse into ONE row: it is one authorization question.
    expect(rows.filter((x) => x.file.endsWith("publish.js"))).toHaveLength(1);
  });

  it("does not flag a handler with a marker in scope", () => {
    const r = row(rows, "admin");
    expect(r?.state).toBe("guarded");
    expect(r?.guards.map((g) => g.hint)).toContain("requireAuth");
  });

  it("does not credit one handler with its neighbour's guard", () => {
    expect(row(rows, "guardedOne")?.state).toBe("guarded");
    expect(row(rows, "openOne")?.state).toBe("unguarded");
    // The narrower scope is what makes that possible. The extractor often omits
    // `endLine` (measured: all 49 handlers of one real monorepo), so a file-wide
    // fallback would report BOTH as guarded.
    expect(row(rows, "guardedOne")?.scope).not.toBe("file");
  });

  it("asks nothing of code that reads no request data", () => {
    expect(rows.some((r) => r.file.endsWith("util.js"))).toBe(false);
  });

  it("gives a row a stable id across re-emissions and edits", () => {
    // Same file + same handler ⇒ same id, even though the body changed and the
    // line moved. A verdict written yesterday still names the same row today,
    // which is what lets `--apply` fold a worklist filled over several sessions.
    const edited = matrixOf({
      "src/publish.js": `// a comment nobody had written yet
export function publish(req, res) {
  res.end(req.body.id);
}
`,
    });
    expect(edited[0]?.id).toBe(row(rows, "publish")?.id);
    expect(edited[0]?.line).not.toBe(row(rows, "publish")?.line);
  });

  it("counts the matrix for the command line", () => {
    const t = guardTotals(rows);
    expect(t.handlers).toBe(rows.length);
    expect(t.unguarded).toBe(rows.filter((r) => r.state === "unguarded").length);
  });
});

describe("guard matrix — the verdict is the auditor's", () => {
  it("turns an unguarded row into a discovery citing the row's own line", () => {
    const rows = matrixOf({ "src/open.js": "export function open(req, res) {\n  res.end(req.body.x);\n}\n" });
    const r = row(rows, "open")!;
    const d = guardDiscovery(r, "No middleware, and Hasura is called with the admin secret.");
    expect(d.category).toBe("authz");
    expect(d.cwe).toBe("CWE-306");
    // The citation is a line the engine READ to build the row, so it resolves by
    // construction and passes the grounding gate for the same reason every
    // `investigate` discovery does.
    expect(d.file).toBe(r.file);
    expect(d.line).toBe(r.line);
    expect(d.message).toContain("No middleware");
    // `high`, not `critical`: whether an open handler is catastrophic depends on
    // what it DOES, which the matrix does not know and `verify` decides.
    expect(d.severity).toBe("high");
  });

  it("renders a brief that says a marker is a candidate, not a proof", () => {
    const md = renderGuardsMd(matrixOf({ "src/open.js": "export function open(req, res) {\n  res.end(req.body.x);\n}\n" }));
    expect(md).toContain("No visible guard");
    expect(md).toContain("candidate");
    expect(md).toContain("guards --apply");
  });

  it("says so plainly when nothing reads a request", () => {
    const md = renderGuardsMd([]);
    expect(md).toContain("No handler reads request data");
  });
});

// A repo with no authentication at all is ONE fact, not N findings.
//
// Tested against a public information site: 21 handlers, 21 unguarded, each
// demanding an `intentionally-public` verdict for a single architectural truth.
describe("guard matrix — an application with no auth anywhere", () => {
  const rows = matrixOf({
    "src/a.js": "export function a(req, res) {\n  res.end(req.query.x);\n}\n",
    "src/b.js": "export function b(req, res) {\n  res.end(req.body.y);\n}\n",
    "src/c.js": "export function c(req, res) {\n  res.end(req.params.z);\n}\n",
  });

  it("says so once instead of asking the same question N times", () => {
    expect(guardTotals(rows).noAuthAnywhere).toBe(true);
    const md = renderGuardsMd(rows);
    expect(md).toContain("No authentication mechanism anywhere");
    expect(md).toContain("one architectural fact");
    // …and names the two answers worth distinguishing.
    expect(md).toContain("public by design");
    expect(md).toMatch(/gateway|ingress|proxy/);
  });

  it("stays quiet when the repo does have auth somewhere", () => {
    const mixed = matrixOf({
      "src/open.js": "export function open(req, res) {\n  res.end(req.query.x);\n}\n",
      "src/guarded.js": "export function guarded(req, res) {\n  if (!requireAuth(req)) return;\n  res.end(req.body.y);\n}\n",
      "src/other.js": "export function other(req, res) {\n  res.end(req.params.z);\n}\n",
    });
    expect(guardTotals(mixed).noAuthAnywhere).toBe(false);
    expect(renderGuardsMd(mixed)).not.toContain("No authentication mechanism anywhere");
  });

  it("does not fire on a single badly-written route file", () => {
    // Two handlers is a file, not an architecture.
    const tiny = matrixOf({ "src/only.js": "export function a(req, res) {\n  res.end(req.query.x);\n}\n" });
    expect(guardTotals(tiny).noAuthAnywhere).toBe(false);
  });
});
