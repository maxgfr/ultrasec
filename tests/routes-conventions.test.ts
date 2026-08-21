import { describe, it, expect } from "vitest";
import { join } from "node:path";
import { scanRepo } from "../src/scan.js";
import { buildGraph } from "../src/graph.js";
import { buildAttackSurface } from "../src/map.js";
import { buildContextScaffold } from "../src/context.js";
import { buildInvestigateWorklist } from "../src/investigate.js";
import { findRouteEntryPoints } from "../src/catalog.js";
import { expandBraces } from "../src/walk.js";

// Issue #10 (defect 1). `findSources` is a line-content scan, and in a
// file-system-routed framework the fact that makes a file an HTTP entry point is
// its PATH. A handler that never spells out `req.query` — it destructures the
// body, reads `params`, or forwards `req` whole — was invisible to `context`,
// `map`, the taint seeder and, through them, to `investigate`.
//
// The fixture is a workspace monorepo whose HTTP surface spans four ecosystems
// and three packages, with the framework dependency deliberately NOT at the root.

const FIXTURE = join(import.meta.dirname, "fixtures", "routes-conventions");
const scan = scanRepo(FIXTURE);
const surface = buildAttackSurface(scan);
const scaffold = buildContextScaffold(FIXTURE, scan, surface);
const entryFiles = new Set(scaffold.entryPoints.map((e) => e.file));

describe("framework detection reads every manifest, not just the root's", () => {
  it("detects next.js from a workspace package's package.json", () => {
    // The dependency lives in services/web/package.json. Reading only the root
    // reported `frameworks: —` on a repo whose whole surface was a Next.js app.
    expect(scaffold.frameworks).toContain("next.js");
  });
});

describe("entry points by convention — across ecosystems", () => {
  it("finds a Pages-Router handler whose body never names req.query", () => {
    expect(entryFiles.has("services/web/pages/api/publish.ts")).toBe(true);
  });

  it("finds a named function assigned then default-exported", () => {
    expect(entryFiles.has("services/web/pages/api/storage.ts")).toBe(true);
  });

  it("finds a bare instance used as the default export — no function declaration at all", () => {
    expect(entryFiles.has("services/web/pages/api/proxy.ts")).toBe(true);
  });

  it("finds App-Router verb exports", () => {
    const lines = scaffold.entryPoints.filter((e) => e.file === "services/web/app/api/users/route.ts").map((e) => e.line);
    expect(lines).toContain(3); // export async function GET
    expect(lines).toContain(7); // export async function DELETE
  });

  it("does NOT report a route module's private helper as an endpoint", () => {
    // `function helper()` at :11 is not exported — a verb-export rule, not the
    // catch-all, applies to App-Router files precisely so this stays quiet.
    const lines = scaffold.entryPoints.filter((e) => e.file === "services/web/app/api/users/route.ts").map((e) => e.line);
    expect(lines).not.toContain(11);
  });

  it("finds a Rails controller action, a serverless handler and a web-root PHP script", () => {
    expect(entryFiles.has("app/controllers/users_controller.rb")).toBe(true);
    expect(entryFiles.has("functions/handler.py")).toBe(true);
    expect(entryFiles.has("public/upload.php")).toBe(true);
  });

  it("does not turn ordinary library code into an entry point", () => {
    // services/web/lib/publish.ts is exported and callable, but it is not under
    // any routes directory — the convention is about WHERE, not just what.
    expect(entryFiles.has("services/web/lib/publish.ts")).toBe(false);
    expect(entryFiles.has("services/batch/ingest.py")).toBe(false);
  });

  it("emits at most one entry point per line when two conventions overlap", () => {
    const seen = new Set<string>();
    for (const e of scaffold.entryPoints) {
      const key = `${e.file}:${e.line}`;
      expect(seen.has(key), `duplicate entry point at ${key}`).toBe(false);
      seen.add(key);
    }
  });
});

describe("investigate regions — a monorepo is not one region", () => {
  const regions = buildInvestigateWorklist(surface, buildGraph(scan));
  const byName = new Map(regions.map((r) => [r.region, r]));

  it("keys regions on the workspace package, not the first path segment", () => {
    // Both live under services/. Collapsing them into one `services` region is
    // how an entire web app came to share a budget with a batch pipeline.
    expect(byName.has("services/web")).toBe(true);
    expect(byName.has("services/batch")).toBe(true);
    expect(byName.has("services")).toBe(false);
  });

  it("ranks the internet-facing region above the batch one", () => {
    // The score used to count sinks only, so a directory full of routes and no
    // local sink scored 0 and sorted last.
    expect(regions[0]!.region).toBe("services/web");
    expect(byName.get("services/web")!.score).toBeGreaterThan(byName.get("services/batch")!.score);
  });

  it("puts the API routes in the web region's file list", () => {
    const files = byName.get("services/web")!.files;
    expect(files).toContain("services/web/pages/api/publish.ts");
    expect(files).toContain("services/web/app/api/users/route.ts");
  });
});

describe("findRouteEntryPoints", () => {
  it("is a no-op for a path matching no convention", () => {
    expect(findRouteEntryPoints("src/lib/util.ts", "export function f() {}\n")).toEqual([]);
  });

  it("matches a routes directory at any depth", () => {
    const hits = findRouteEntryPoints("a/b/c/pages/api/x.ts", "export default function handler(req, res) {}\n");
    expect(hits.map((h) => h.line)).toEqual([1]);
    expect(hits[0]!.kind).toBe("http");
  });
});

describe("expandBraces", () => {
  it("expands alternation into plain globs", () => {
    expect(expandBraces("**/x.{js,ts}").sort()).toEqual(["**/x.js", "**/x.ts"]);
  });

  it("expands nested alternation", () => {
    expect(expandBraces("{a,{b,c}}/x").sort()).toEqual(["a/x", "b/x", "c/x"]);
  });

  it("leaves a pattern without braces, and an unbalanced one, alone", () => {
    expect(expandBraces("**/x.ts")).toEqual(["**/x.ts"]);
    expect(expandBraces("**/{x.ts")).toEqual(["**/{x.ts"]);
  });
});
