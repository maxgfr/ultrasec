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
    expect(guardTotals(rows).noMarkerAnywhere).toBe(true);
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
    expect(guardTotals(mixed).noMarkerAnywhere).toBe(false);
    expect(renderGuardsMd(mixed)).not.toContain("No authentication mechanism anywhere");
  });

  it("does not fire on a single badly-written route file", () => {
    // Two handlers is a file, not an architecture.
    const tiny = matrixOf({ "src/only.js": "export function a(req, res) {\n  res.end(req.query.x);\n}\n" });
    expect(guardTotals(tiny).noMarkerAnywhere).toBe(false);
  });
});

// ── The throttle lens ────────────────────────────────────────────────────────
//
// The same crossing, asked of rate limiting. Motivated by the audit of
// code-du-travail-numerique, finding A4: `grep -E 'rate|429'` across the API
// returned nothing, and the auditor wrote that up as ONE medium finding. The
// engine could not produce that fact at all — "missing rate limiting" lived in a
// coverage hint string that no run ever answered.
describe("guards --lens throttle", () => {
  const throttleOf = (files: Record<string, string>): GuardRow[] => buildGuardMatrix(scanRepo(repoWith(files)), "throttle");

  const NO_LIMIT: Record<string, string> = {
    "src/api/search.js": "export function search(req, res) {\n  res.end(lookup(req.query.q));\n}\n",
    "src/api/nps.js": "export function nps(req, res) {\n  res.end(store(req.body));\n}\n",
    "src/api/idcc.js": "export function idcc(req, res) {\n  res.end(fetchIdcc(req.query.cp));\n}\n",
  };

  it("reports 'no rate limiting anywhere' as ONE architectural fact", () => {
    const rows = throttleOf(NO_LIMIT);
    const t = guardTotals(rows);
    expect(t.handlers).toBe(3);
    expect(t.unguarded).toBe(3);
    expect(t.noMarkerAnywhere).toBe(true);

    const md = renderGuardsMd(rows, undefined, "throttle");
    expect(md).toContain("No rate limiting anywhere in this repository");
    expect(md).toContain(`one architectural fact, not ${t.handlers} findings`);
    // It must send the reader to the place the limit may actually live.
    expect(md).toMatch(/ingress|CDN|gateway|WAF/);
    // …and it must NOT be the auth lens's paragraph.
    expect(md).not.toContain("No authentication mechanism anywhere");
  });

  it("recognises a limiter in scope, and asks the right thing about it", () => {
    const rows = throttleOf({
      ...NO_LIMIT,
      "src/api/limited.js": "export function limited(req, res) {\n  if (!rateLimiter.take(req.ip)) return res.status(429).end();\n  res.end(req.query.x);\n}\n",
    });
    const limited = rows.find((r) => r.handler === "limited");
    expect(limited?.state).toBe("guarded");
    expect(guardTotals(rows).noMarkerAnywhere).toBe(false);

    const md = renderGuardsMd(rows, undefined, "throttle");
    expect(md).toContain("A rate limit is visible");
    expect(md).toContain("count the wrong key");
  });

  it("separates an AUTH endpoint from a capacity problem", () => {
    const rows = throttleOf({
      ...NO_LIMIT,
      "src/api/signin.js": "export function signin(req, res) {\n  res.end(check(req.body.email, req.body.password));\n}\n",
    });
    const signin = rows.find((r) => r.handler === "signin");
    expect(signin?.loginShape).toBe(true);
    expect(rows.find((r) => r.handler === "search")?.loginShape).toBeUndefined();
    expect(guardTotals(rows).unguardedLoginShaped).toBe(1);

    const md = renderGuardsMd(rows, undefined, "throttle");
    expect(md).toContain("auth endpoint — brute force / account enumeration");
    // The auth-shaped row is listed BEFORE the ordinary ones: the worklist's
    // order is the order someone reads it in.
    expect(md.indexOf("src/api/signin.js")).toBeLessThan(md.indexOf("src/api/search.js"));
  });

  it("files an unthrottled auth endpoint as CWE-307, and an ordinary one as CWE-770", () => {
    const rows = throttleOf({ ...NO_LIMIT, "src/api/signin.js": "export function signin(req, res) {\n  res.end(check(req.body.email));\n}\n" });
    const login = guardDiscovery(rows.find((r) => r.handler === "signin")!, undefined, "throttle");
    expect(login.cwe).toBe("CWE-307");
    expect(login.severity).toBe("high");
    expect(login.message).toContain("CWE-204"); // account enumeration named, not assumed
    expect(login.category).toBe("other");

    const plain = guardDiscovery(rows.find((r) => r.handler === "search")!, undefined, "throttle");
    expect(plain.cwe).toBe("CWE-770");
    expect(plain.severity).toBe("medium");
    // Every throttle discovery must name the refutation that beats it.
    expect(plain.message).toMatch(/ingress|CDN|gateway/);
  });

  it("gives a throttle row its own id, so the two lenses cannot collide", () => {
    const dir = repoWith({ "src/api/search.js": NO_LIMIT["src/api/search.js"]! });
    const auth = buildGuardMatrix(scanRepo(dir), "auth");
    const thr = buildGuardMatrix(scanRepo(dir), "throttle");
    expect(auth[0]!.id).not.toBe(thr[0]!.id);
    // The auth lens keeps its historical id and carries no `lens` marker, so a
    // GUARDS.json written before lenses existed still names the same rows.
    expect(auth[0]!.lens).toBeUndefined();
    expect(thr[0]!.lens).toBe("throttle");
  });
});

// ── Decorators are part of the handler they sit on ──────────────────────────
//
// Observed on a real Sanic app (egapro, `packages/api/egapro/views.py`): every
// handler decorated `@tokens.require` / `@ensure_owner` was scoped from its
// `def` line down, so the guard in the canonical Python position — ABOVE the
// `def` — was never searched. Measured on both extraction tiers: a Python
// function's symbol line is its `def` (decorators excluded), a TypeScript
// method's is its name (decorators excluded); only Java's AST tier folds
// annotations into the symbol. Worse, the approximate scope (no `endLine`, the
// regex tier's normal case) ran to the line before the NEXT `def` — which is the
// next handler's decorator block, credited to the handler above it.
describe("guard matrix — decorators and annotations", () => {
  it("credits a Python view with the decorator above its def", () => {
    const rows = matrixOf({
      "app/views.py": `from django.http import HttpResponse

@login_required
def private(request):
    return HttpResponse(request.GET["a"])

def public(request):
    return HttpResponse(request.GET["b"])
`,
    });
    expect(row(rows, "private")?.state).toBe("guarded");
    expect(row(rows, "private")?.guards.map((g) => g.line)).toEqual([3]);
    expect(row(rows, "public")?.state).toBe("unguarded");
  });

  it("does not credit a handler with the NEXT handler's decorator", () => {
    // The worse half: an open handler followed by a guarded one read as guarded,
    // because the approximate scope ran up to the next `def`.
    const rows = matrixOf({
      "app/views.py": `def open_view(request):
    return request.GET["a"]

@app.route("/closed",
           methods=["POST"])
@login_required
def closed_view(request):
    return request.GET["b"]
`,
    });
    expect(row(rows, "open_view")?.state).toBe("unguarded");
    expect(row(rows, "open_view")?.scope).toBe("approx");
    // A decorator whose arguments span lines is still one block with the def.
    expect(row(rows, "closed_view")?.state).toBe("guarded");
  });

  it("does not reach past a closed function body into an earlier decorator", () => {
    // `@login_required` belongs to `a`; nothing but the body of `a` separates it
    // from `b`, and a naive "keep walking up to the next @" would hand it to `b`.
    const rows = matrixOf({
      "app/views.py": `@login_required
def a(request):
    return request.GET["x"]
def b(request):
    return request.GET["y"]
`,
    });
    expect(row(rows, "a")?.state).toBe("guarded");
    expect(row(rows, "b")?.state).toBe("unguarded");
  });

  it("credits a Spring method with the annotation above it", () => {
    const rows = matrixOf({
      "src/main/java/UserController.java": `@RestController
public class UserController {
  @Secured("ROLE_ADMIN")
  @GetMapping("/admin")
  public String admin(@RequestParam String q) {
    return q;
  }

  @GetMapping("/open")
  public String open(@RequestParam String q) {
    return q;
  }
}
`,
    });
    expect(row(rows, "admin")?.state).toBe("guarded");
    // The annotation itself is the marker — `@Secured` has no call-site twin.
    expect(row(rows, "admin")?.guards.map((g) => g.hint)).toContain("@Secured");
    expect(row(rows, "open")?.state).toBe("unguarded");
  });

  it("holds on the AST tier's shape too, where the extent is exact", () => {
    // What the AST tier records for this file, as measured: the method starts at
    // its NAME, below its decorators, with an exact `endLine`. The regex tier
    // extracts no TypeScript methods at all, so the shape is pinned here rather
    // than depending on which grammars this machine has cached.
    const dir = repoWith({
      "src/users.controller.ts": `export class UsersController {
  @UseGuards(AuthGuard)
  @Get()
  find(@Query() q: string) {
    return q;
  }

  @Post()
  open(@Body() b: unknown) {
    return b;
  }
}
`,
      "app/views.py": `@login_required
def view(request):
    return request.GET["a"]
`,
    });
    const scan = scanRepo(dir);
    const ts = scan.files.find((f) => f.rel === "src/users.controller.ts")!;
    ts.symbols = [
      { name: "UsersController", kind: "class", line: 1, endLine: 12, exported: true },
      { name: "find", kind: "method", line: 4, endLine: 6, exported: true },
      { name: "open", kind: "method", line: 9, endLine: 11, exported: true },
    ];
    const py = scan.files.find((f) => f.rel === "app/views.py")!;
    py.symbols = [{ name: "view", kind: "function", line: 2, endLine: 3, exported: true }];

    const rows = buildGuardMatrix(scan);
    expect(row(rows, "find")?.state).toBe("guarded");
    expect(row(rows, "find")?.guards.map((g) => g.hint)).toContain("@UseGuards");
    expect(row(rows, "find")?.scope).toBe("symbol");
    expect(row(rows, "open")?.state).toBe("unguarded");
    expect(row(rows, "view")?.state).toBe("guarded");
  });
});

// A Server Action reads no `req` — its arguments ARE the request body — so the
// only way it reaches the matrix is as an entry point by convention. Before, it
// never did: `guards` on a real Next.js app listed none of ~20 action files, and
// the audit's critical authorization bug lived in one of them.
describe("guard matrix — Next.js Server Actions", () => {
  const rows = matrixOf({
    "src/app/(default)/rattachement/actions.ts": `"use server";

import { getServerSession } from "next-auth";

export async function addSirens(sirens: string[]) {
  await db.insert(sirens);
}

export async function listSirens() {
  const session = await getServerSession(authConfig);
  if (!session) throw new Error("unauthorized");
  return db.list(session.user.id);
}
`,
  });

  it("asks the authorization question of every exported action", () => {
    expect(row(rows, "addSirens")?.state).toBe("unguarded");
    expect(row(rows, "addSirens")?.kinds).toEqual(["http"]);
  });

  it("recognises NextAuth's session check as a guard", () => {
    expect(row(rows, "listSirens")?.state).toBe("guarded");
    expect(row(rows, "listSirens")?.guards.map((g) => g.hint)).toContain("getServerSession");
  });
});
