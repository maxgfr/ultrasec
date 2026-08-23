import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runRender } from "../src/commands/render.js";
import { renderHtml } from "../src/render/html.js";
import { renderReport, renderSummary } from "../src/render/report.js";
import type { Dossier } from "../src/store.js";
import type { Finding, Status } from "../src/types.js";

function finding(over: Partial<Finding> = {}): Finding {
  return {
    id: over.id ?? "f1",
    category: "taint",
    cwe: "CWE-89",
    title: "SQL injection: untrusted input reaches query()",
    severity: "high",
    confidence: "medium",
    message: "Tainted input may reach a raw SQL query.",
    tool: "ultrasec",
    status: "open",
    source: { file: "src/api.ts", line: 3 },
    sink: { file: "src/db.ts", line: 9 },
    path: [
      { file: "src/api.ts", line: 3, why: "source: req.query.id" },
      { file: "src/db.ts", line: 9, why: "sql sink: query()" },
    ],
    ...over,
  } as Finding;
}

function dossier(findings: Finding[]): Dossier {
  return {
    manifest: {
      version: "9.9.9",
      schemaVersion: 9,
      repo: "/repo",
      generatedNote: "note",
      languages: ["javascript"],
      toolsRun: [],
      counts: { findings: findings.length, bySeverity: { critical: 0, high: findings.length, medium: 0, low: 0, info: 0 } },
    } as Dossier["manifest"],
    findings,
    graph: { files: [], edges: [], symbolDefs: {} },
  };
}

let run = "";

beforeEach(() => {
  run = mkdtempSync(join(tmpdir(), "ultrasec-gate-"));
});
afterEach(() => {
  rmSync(run, { recursive: true, force: true });
});

function seed(findings: Finding[]): void {
  const d = dossier(findings);
  writeFileSync(join(run, "manifest.json"), JSON.stringify(d.manifest));
  writeFileSync(join(run, "findings.json"), JSON.stringify(d.findings));
  writeFileSync(join(run, "graph.json"), JSON.stringify(d.graph));
}

describe("render gate", () => {
  it("exits 1 when a HIGH source-code candidate was never read", () => {
    seed([finding()]);
    expect(runRender({ _: ["render"], flags: { run, "no-journal": true } })).toBe(1);
  });

  it("writes every artifact anyway — a refused report is worse than a flagged one", () => {
    seed([finding()]);
    runRender({ _: ["render"], flags: { run, "no-journal": true } });
    for (const name of ["SUMMARY.md", "REPORT.md", "index.html"]) {
      expect(existsSync(join(run, name)), name).toBe(true);
      expect(readFileSync(join(run, name), "utf8").length).toBeGreaterThan(0);
    }
  });

  it("exits 0 with --draft, an acknowledged incomplete audit", () => {
    seed([finding()]);
    expect(runRender({ _: ["render"], flags: { run, draft: true, "no-journal": true } })).toBe(0);
  });

  it("exits 0 once every code candidate is decided", () => {
    for (const status of ["confirmed", "needs-human", "dismissed"] as Status[]) {
      seed([finding({ status })]);
      expect(runRender({ _: ["render"], flags: { run, "no-journal": true } }), status).toBe(0);
    }
  });

  it("exits 0 on open dependency advisories — a ranked list is the prescribed outcome", () => {
    seed([finding({ id: "cve", category: "dep", pkg: "lodash", severity: "critical", path: undefined, source: undefined })]);
    expect(runRender({ _: ["render"], flags: { run, "no-journal": true } })).toBe(0);
  });
});

describe("the banner travels with the artifact", () => {
  it("opens the HTML, the report and the summary", () => {
    const d = dossier([finding()]);
    expect(renderHtml(d)).toContain("Incomplete audit");
    expect(renderReport(d)).toContain("Incomplete audit");
    expect(renderSummary(d)).toContain("Incomplete audit");
  });

  it("replaces the summary sentence that reads as a clean bill of health", () => {
    // "No confirmed issues" with nothing adjudicated means undecided, not safe.
    const md = renderSummary(dossier([finding()]));
    expect(md).not.toContain("No confirmed issues.");
    expect(md).toContain("nothing was decided");
  });

  it("says nothing when the audit is complete", () => {
    const d = dossier([finding({ status: "confirmed", verdict: "supported", exploitPath: "GET /x?id=1 OR 1=1" })]);
    for (const out of [renderHtml(d), renderReport(d), renderSummary(d)]) {
      expect(out).not.toContain("Incomplete audit");
    }
  });
});

describe("layout", () => {
  // The bug: `.cols` declares two tracks, and a run with nothing confirmed and
  // nothing needs-human produced an empty rail — so the single <main> child
  // auto-placed into the 260px rail track and the whole report rendered in a
  // ribbon. Three independent things now prevent it.

  it("always renders a rail, even with no findings at all", () => {
    // Section anchors, not just actionable findings. The page with the most to
    // navigate used to be the one page with no navigation.
    const html = renderHtml(dossier([]));
    expect(html).toContain('<nav class="rail"');
    expect(html).toContain('href="#summary"');
    expect(html).toContain('href="#coverage"');
  });

  it("pins main to the last track so implicit placement can never squeeze it", () => {
    expect(renderHtml(dossier([finding()]))).toContain("grid-column:-2");
  });

  it("keeps a one-column fallback in the stylesheet for an empty rail", () => {
    expect(renderHtml(dossier([]))).toContain(".cols.norail { grid-template-columns:minmax(0,1fr)");
  });

  it("widens the page but not the prose", () => {
    const html = renderHtml(dossier([finding()]));
    expect(html).toContain("max-width:1600px");
    expect(html).toContain(".prose { max-width:78ch; }");
  });
});

describe("surfaces", () => {
  const mixed = [
    finding({ id: "code1" }),
    finding({
      id: "cve1",
      category: "dep",
      pkg: "lodash",
      severity: "critical",
      path: undefined,
      source: undefined,
      sink: { file: "pnpm-lock.yaml", line: 1 },
    }),
    finding({ id: "sec1", category: "secret", severity: "high", path: undefined, source: undefined, sink: { file: ".env", line: 2 } }),
  ];

  it("gives each surface its own section", () => {
    const html = renderHtml(dossier(mixed));
    expect(html).toContain('<section id="code"');
    expect(html).toContain('<section id="supply"');
    expect(html).toContain('<section id="deps"');
    // The flat "Unadjudicated candidates" table is what buried the flows.
    expect(html).not.toContain('<section id="open"');
  });

  it("folds the dependency section shut and rolls it up per package", () => {
    const html = renderHtml(dossier(mixed));
    const deps = html.slice(html.indexOf('id="deps"'));
    expect(deps).toContain("<details><summary>Show 1 advisory, rolled up per package");
    expect(deps).toContain('<td class="pkg">lodash</td>');
  });

  it("opens the code section with the attack surface", () => {
    expect(renderHtml(dossier(mixed))).toContain("Attack surface &mdash; 1 entry point(s)");
  });

  it("splits the same way in Markdown", () => {
    const md = renderReport(dossier(mixed));
    expect(md).toContain("## Your source code — undecided");
    expect(md).toContain("## Secrets & configuration — undecided");
    expect(md).toContain("## Dependency advisories — undecided");
  });
});
