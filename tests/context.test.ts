import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanRepo } from "../src/scan.js";
import { buildAttackSurface } from "../src/map.js";
import { buildContextScaffold, loadContextDoc, compactContextDoc } from "../src/context.js";
import { renderFindingDossier } from "../src/dossier.js";
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
});
