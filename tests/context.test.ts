import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanRepo } from "../src/scan.js";
import { buildAttackSurface } from "../src/map.js";
import { buildContextScaffold, loadContextDoc, compactContextDoc } from "../src/context.js";
import { dossierContext } from "../src/commands/dossier.js";
import { renderFamilyDossier, renderFindingDossier } from "../src/dossier.js";
import type { Finding } from "../src/types.js";
import type { Graph } from "../src/graph.js";

const FIXTURE = join(import.meta.dirname, "fixtures", "vuln-express");

function scaffoldOf(repo: string) {
  const scan = scanRepo(repo);
  return buildContextScaffold(repo, scan, buildAttackSurface(scan));
}

describe("buildContextScaffold", () => {
  const s = scaffoldOf(FIXTURE);

  it("detects express as a framework from package.json", () => {
    expect(s.frameworks).toContain("express");
  });

  it("captures the HTTP entry point (req.query) in server.js", () => {
    const http = s.entryPoints.filter((e) => e.kind === "http");
    expect(http.length).toBeGreaterThan(0);
    expect(http.some((e) => e.file === "src/server.js")).toBe(true);
  });

  it("captures the parameterized-query sanitizer in db.js", () => {
    expect(s.sanitizers.some((x) => x.file === "src/db.js" && x.kind === "sql")).toBe(true);
  });

  it("reports the placeholder rule only where a SQL sink actually is", () => {
    // `?`, `:name` and `@scope` are ordinary TypeScript punctuation. Matching
    // them anywhere made 3% of every line an "SQL sanitizer" — and because that
    // rule is first in the catalog and the loop breaks, it also shadowed every
    // real sanitizer behind it. On a real audit all 40 slots went to
    // `.husky/`, `lighthouserc.cjs` and `app/a…`, and the repo's only HTML
    // sanitizer never appeared.
    const sql = s.sanitizers.filter((x) => x.kind === "sql");
    for (const hit of sql) {
      const line = readFileSync(join(FIXTURE, hit.file), "utf8").split(/\r?\n/)[hit.line - 1]!;
      expect(line, `${hit.file}:${hit.line}`).toMatch(/query|execute|prepare/i);
    }
  });

  it("keeps the real sanitizer when the cap bites, instead of an alphabetical prefix", () => {
    // The defect, reproduced: 60 alphabetically-early files matching only the
    // generic type-coercion rule, and the project's ACTUAL sanitizer in a file
    // sorting last. A path-sorted `slice(0, 40)` returns a prefix, not a sample,
    // so on a real audit all 40 slots went to `.husky/`, `lighthouserc.cjs` and
    // `app/a…` while the repo's only HTML sanitizer — the subject of two of its
    // five high findings — never appeared at all.
    const repo = mkdtempSync(join(tmpdir(), "usec-sanitizer-"));
    for (let i = 0; i < 60; i++) {
      writeFileSync(join(repo, `aaa${String(i).padStart(3, "0")}.js`), `const n = parseInt(process.argv[2], 10);\nmodule.exports = n;\n`);
    }
    writeFileSync(join(repo, "zzz-sanitizer.js"), `const DOMPurify = require("dompurify");\nmodule.exports = (h) => DOMPurify.sanitize(h);\n`);

    const sanitizers = scaffoldOf(repo).sanitizers;
    expect(sanitizers.some((x) => x.file === "zzz-sanitizer.js")).toBe(true);
  });

  it("infers an HTTP trust boundary and an auth note", () => {
    expect(s.trustBoundaries.some((t) => /HTTP request handlers/.test(t))).toBe(true);
    // no auth middleware in the fixture → the "intentionally public?" note
    expect(s.trustBoundaries.some((t) => /No auth\/authorization middleware/.test(t))).toBe(true);
  });

  it("is deterministic (id-sorted, bounded)", () => {
    const again = scaffoldOf(FIXTURE);
    expect(again).toEqual(s);
  });
});

describe("loadContextDoc", () => {
  it("returns undefined when no CONTEXT.md exists", () => {
    const run = mkdtempSync(join(tmpdir(), "ultrasec-ctx-"));
    expect(loadContextDoc(run)).toBeUndefined();
  });

  it("returns undefined for an empty/whitespace CONTEXT.md", () => {
    const run = mkdtempSync(join(tmpdir(), "ultrasec-ctx-"));
    writeFileSync(join(run, "CONTEXT.md"), "   \n\n");
    expect(loadContextDoc(run)).toBeUndefined();
  });

  it("returns the trimmed prose when present", () => {
    const run = mkdtempSync(join(tmpdir(), "ultrasec-ctx-"));
    writeFileSync(join(run, "CONTEXT.md"), "\n# About\nAuth via JWT on /admin/*.\n");
    expect(loadContextDoc(run)).toBe("# About\nAuth via JWT on /admin/*.");
  });
});

describe("renderFindingDossier — CONTEXT.md injection (back-compat)", () => {
  const graph: Graph = { files: [], edges: [], symbolDefs: {} };
  const f: Finding = {
    id: "a",
    category: "taint",
    cwe: "CWE-89",
    title: "SQLi",
    severity: "high",
    confidence: "low",
    message: "candidate",
    tool: "ultrasec",
    status: "open",
    sink: { file: "src/db.js", line: 6 },
  };

  it("omits the Project context section when no context is given (byte-identical to today)", () => {
    const without = renderFindingDossier(FIXTURE, graph, f);
    expect(without).not.toContain("## Project context");
    // explicit undefined behaves identically to the omitted arg
    expect(renderFindingDossier(FIXTURE, graph, f, undefined)).toBe(without);
  });

  it("includes the Project context section verbatim when context is given", () => {
    const ctx = "Auth via JWT on /admin/*; ORM parameterizes all queries.";
    const out = renderFindingDossier(FIXTURE, graph, f, ctx);
    expect(out).toContain("## Project context");
    expect(out).toContain(ctx);
    // the section sits before the decision prompt
    expect(out.indexOf("## Project context")).toBeLessThan(out.indexOf("## What to decide"));
  });
});

describe("renderFamilyDossier — `dossier a,b,c --brief`", () => {
  const graph: Graph = { files: [], edges: [], symbolDefs: {} };
  const m = (id: string, line: number): Finding => ({
    id,
    category: "taint",
    cwe: "CWE-89",
    title: "SQLi",
    severity: "high",
    confidence: "low",
    message: `candidate ${id}`,
    tool: "ultrasec",
    status: "open",
    sink: { file: "src/db.js", line },
  });

  it("prints the context and the checklist once, the first member in full, a line + ±3 window per other member", () => {
    const ctx = "Auth via JWT on /admin/*.";
    const out = renderFamilyDossier(FIXTURE, graph, [m("a", 6), m("b", 7), m("c", 8)], { context: ctx, brief: true });
    expect(out.split("## Project context").length - 1).toBe(1);
    expect(out.split("## How to verify").length - 1).toBe(1);
    expect(out).toContain("# a — SQLi");
    expect(out).toContain("## What to decide\ncandidate a");
    expect(out).toContain("## Other members (2)");
    expect(out).toContain("### b — [high] SQLi · src/db.js:7");
    expect(out).not.toContain("candidate b"); // a member is its location, not a second packet
    // the window is ±3 lines around the member's line, marked
    const win = out.slice(out.indexOf("### b —"), out.indexOf("### c —"));
    expect(win).toMatch(/>> {4}7 \|/);
    expect(win).toMatch(/ {3}4 \|/);
    expect(win).not.toMatch(/ {3}3 \|/);
    expect(out.indexOf("## How to verify")).toBeGreaterThan(out.indexOf("### c —"));
  });

  it("a single id renders exactly the one-finding packet", () => {
    expect(renderFamilyDossier(FIXTURE, graph, [m("a", 6)], { brief: true })).toBe(renderFindingDossier(FIXTURE, graph, m("a", 6), { brief: true }));
  });
});

describe("compactContextDoc — the adjudication-bearing sections only", () => {
  // Shaped like the CONTEXT.md a real audit produced: purpose and stack take
  // most of the document, and `dossier` reprinted all of it before every one of
  // dozens of candidates.
  const DOC = [
    "# CONTEXT — app",
    "## Purpose",
    "Public site for looking up employment law.",
    "## Stack",
    "Next.js 16 App Router, react 19, Elasticsearch v8.",
    "## Trust model / boundaries",
    "1. Anonymous visitor → query/body of the API routes. NOT trusted.",
    "## Hunt list (STRIDE par frontière)",
    "- Boundary 1: Elasticsearch DSL injection, CPU DoS on `q`.",
    "## Exposure: Internet-facing production",
    "## Criticality: high — official public service",
  ].join("\n");

  it("keeps what bears on reachability and severity", () => {
    const out = compactContextDoc(DOC)!;
    expect(out).toContain("Hunt list");
    expect(out).toContain("Exposure");
    expect(out).toContain("Criticality");
    expect(out).toContain("Trust model");
  });

  it("drops the inventory an adjudicator does not re-read per candidate", () => {
    const out = compactContextDoc(DOC)!;
    expect(out).not.toContain("Next.js 16 App Router");
    expect(out).not.toContain("Public site for looking up");
    expect(out.length).toBeLessThan(DOC.length);
  });

  it("returns undefined on an unrecognised layout, so the caller keeps the whole document", () => {
    // Losing the threat model silently would be far worse than printing it.
    expect(compactContextDoc("# CONTEXT\n\nJust prose, no headings.\n")).toBeUndefined();
  });

  it("keeps Exposure:/Criticality: written as plain lines, the form the scaffold asks for", () => {
    const doc = [
      "# CONTEXT",
      "",
      "Exposure: internet-facing",
      "Criticality: standard",
      "",
      "## Purpose",
      "A site.",
      "## Trust boundaries",
      "1. Visitor → API.",
    ].join("\n");
    const out = compactContextDoc(doc)!;
    expect(out).toContain("Exposure: internet-facing");
    expect(out).toContain("Criticality: standard");
    expect(out).toContain("Trust boundaries");
    expect(out).not.toContain("A site.");
  });
});

describe("dossierContext — which CONTEXT.md a dossier prints", () => {
  const DOC = ["# CONTEXT", "## Purpose", "Long purpose prose.", "## Trust boundaries", "1. Visitor → API."].join("\n");

  it("--brief prints the compact context: the batch packet must not repeat the whole document per id", () => {
    const out = dossierContext(DOC, { brief: true })!;
    expect(out).toContain("Trust boundaries");
    expect(out).not.toContain("Long purpose prose.");
  });

  it("the default single-finding dossier keeps the whole document", () => {
    expect(dossierContext(DOC, {})).toBe(DOC);
  });

  it("--no-context wins over everything", () => {
    expect(dossierContext(DOC, { brief: true, noContext: true })).toBeUndefined();
  });

  it("an unrecognised layout stays whole even under --brief", () => {
    const prose = "# CONTEXT\n\nJust prose.";
    expect(dossierContext(prose, { brief: true })).toBe(prose);
  });
});

describe("renderFindingDossier — reachability evidence, stated not decided", () => {
  // #13's third ask was "require a real flow edge into the sink's attribute".
  // The engine does not enforce it: enumeration closes a path on co-location,
  // and tightening that mechanically trades recall on DOM XSS — the class where
  // real bugs live. So it SHOWS whether there is an edge, and the adjudicator
  // can require one.
  const graph: Graph = { files: [], edges: [], symbolDefs: {} };

  function f(over: Partial<Finding>): Finding {
    return {
      id: "x",
      category: "taint",
      title: "DOM XSS",
      severity: "medium",
      confidence: "low",
      message: "m",
      tool: "ultrasec",
      status: "open",
      sink: { file: "a.js", line: 7 },
      ...over,
    };
  }

  it("says CO-LOCATION when the whole path is one file and nothing tracked arrives", () => {
    const md = renderFindingDossier(
      FIXTURE,
      graph,
      f({
        sourceScope: "file",
        dataflow: "unlinked",
        flow: { assigned: "unrelated", tainted: ["frag"] },
        path: [
          { file: "a.js", line: 3, why: "source" },
          { file: "a.js", line: 7, why: "sink" },
        ],
      }),
    );
    expect(md).toContain("## Reachability evidence");
    expect(md).toContain("CO-LOCATION only");
    expect(md).toContain("the walk could have followed it and did not");
  });

  // The case that stops this evidence misleading. A cross-file flow legitimately
  // shows "no tracked binding" because the walk is per-file and the assigned
  // value is a parameter — the domxss bench fixture is exactly that, and it is a
  // TRUE positive.
  it("says EXPECTED when the path crosses files, instead of pointing away from a real flow", () => {
    const md = renderFindingDossier(
      FIXTURE,
      graph,
      f({
        sourceScope: "symbol",
        dataflow: "linked",
        flow: { assigned: "html", tainted: ["frag"] },
        path: [
          { file: "routes.js", line: 3, why: "source" },
          { file: "sink.js", line: 7, why: "sink" },
        ],
      }),
    );
    expect(md).toContain("EXPECTED here");
    expect(md).not.toContain("the walk could have followed it and did not");
  });

  it("confirms an edge when a tracked binding IS in the assigned value", () => {
    const md = renderFindingDossier(
      FIXTURE,
      graph,
      f({
        sourceScope: "symbol",
        flow: { assigned: "frag + suffix", tainted: ["frag"] },
        path: [{ file: "a.js", line: 3, why: "source" }],
      }),
    );
    expect(md).toContain("there IS an edge into the attribute");
  });

  it("omits the whole block when the engine has nothing to say", () => {
    expect(renderFindingDossier(FIXTURE, graph, f({}))).not.toContain("Reachability evidence");
  });
});
