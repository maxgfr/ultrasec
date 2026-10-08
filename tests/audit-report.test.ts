import { describe, it, expect } from "vitest";
import { renderAuditReport, reportStatus, areaOf } from "../src/render/audit-report.js";
import { markdownToHtml, renderReportHtml } from "../src/render/md-html.js";
import type { Dossier } from "../src/store.js";
import type { Finding, Narrative, Severity, Status } from "../src/types.js";

// The single-file report. The size discipline is the point: on a 1,245-candidate
// monorepo run the previous REPORT.md was 746 KB — mostly one row per DISMISSED
// candidate — and still lacked the per-finding scenario · fix · effort · priority
// layout people act on.

let n = 0;
function f(over: Partial<Finding> & { status: Status; severity: Severity }): Finding {
  n++;
  const file = over.sink?.file ?? `apps/api/src/route${n % 40}.ts`;
  return {
    id: over.id ?? `id${String(n).padStart(6, "0")}`,
    category: "taint",
    cwe: "CWE-89",
    title: "SQL injection: untrusted input reaches query()",
    confidence: "medium",
    message: "Tainted input may reach a raw SQL query.",
    tool: "ultrasec",
    source: { file, line: 3 },
    sink: { file, line: 9 + (n % 50) },
    path: [
      { file, line: 3, why: "source" },
      { file, line: 9 + (n % 50), why: "sink" },
    ],
    ...over,
  } as Finding;
}

function dossier(findings: Finding[]): Dossier {
  return {
    manifest: {
      version: "9.9.9",
      schemaVersion: 11,
      repo: "/repo",
      generatedNote: "note",
      languages: ["typescript"],
      toolsRun: ["semgrep"],
      counts: { findings: findings.length, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } },
      frameworks: [{ id: "express", title: "Express", dir: "apps/api", file: "apps/api/package.json", line: 1 }],
    } as unknown as Dossier["manifest"],
    findings,
    graph: { files: [], edges: [], symbolDefs: {} },
  };
}

const workflow = (i: number, status: Status): Finding =>
  f({
    status,
    severity: "medium",
    category: "config",
    cwe: "CWE-829",
    title: "GitHub Action not pinned to a commit SHA",
    tool: "zizmor",
    path: undefined,
    source: undefined,
    sink: { file: `.github/workflows/ci${i % 7}.yml`, line: 10 + i },
    message: `uses: some/action@v${i % 4}\n\nVerdict (supported): tag is mutable`,
  });

/** A synthetic run shaped like the incident: ~1,245 candidates, most dismissed. */
function largeRun(): Dossier {
  n = 0;
  const findings: Finding[] = [];
  // 960 dismissed, each with its own refutation argument and title variant.
  for (let i = 0; i < 960; i++)
    findings.push(
      f({
        status: "dismissed",
        severity: i % 10 === 0 ? "high" : "medium",
        title: `Unsafe sink kind ${i % 60}: untrusted input reaches call${i % 60}()`,
        brocard: i % 3 === 0 ? "outside-usage" : undefined,
        verdict: "refuted",
        sink: { file: `packages/lib${i % 25}/src/f${i}.ts`, line: 10 },
        message: `Engine prose for candidate ${i}.\n\nVerdict (refuted): argument number ${i} — the value is a constant from the config loader, never request data, see the caller at packages/lib${i % 25}/src/f${i}.ts:4.`,
      }),
    );
  // 133 confirmed unpinned actions — one family, one card.
  for (let i = 0; i < 133; i++) findings.push(workflow(i, "confirmed"));
  // 90 dependency advisories across 30 packages.
  for (let i = 0; i < 90; i++)
    findings.push(
      f({
        status: "open",
        severity: i % 5 === 0 ? "critical" : "high",
        category: "dep",
        title: `pkg${i % 30}: advisory ${i}`,
        pkg: `pkg${i % 30}`,
        version: "1.0.0",
        fixedVersion: "1.2.0",
        cve: `CVE-2025-${1000 + i}`,
        tool: "trivy",
        path: undefined,
        source: undefined,
        sink: { file: i % 2 ? "apps/api/package-lock.json" : "pnpm-lock.yaml", line: 1 },
      }),
    );
  // 40 confirmed code findings, 22 needs-human.
  for (let i = 0; i < 40; i++)
    findings.push(
      f({
        status: "confirmed",
        severity: i % 4 === 0 ? "critical" : "high",
        title: `Distinct confirmed flow ${i}`,
        exploitPath: `unauthenticated user · sends payload ${i} · reads another tenant's rows`,
        message: `Engine prose.\n\nVerdict (supported): reached through the public route ${i}`,
      }),
    );
  for (let i = 0; i < 22; i++)
    findings.push(f({ status: "needs-human", severity: "high", title: `Unclear authz ${i}`, message: "x\n\nVerdict (partial): guard may be upstream" }));
  return dossier(findings);
}

describe("report structure", () => {
  it("renders every section in the order a reader acts on them", () => {
    const md = renderAuditReport(largeRun());
    const order = [
      "## 1. Executive summary",
      "## 2. Dashboard",
      "## 3. Attack chains",
      "## 4. Follow-up vs previous audit",
      "## 5. Detailed findings",
      "## 6. Secrets & history",
      "## 7. CI/CD & infrastructure exposure",
      "## 8. Dependencies",
      "## 9. Hardening notes",
      "## 10. Coverage & limits",
      "## 11. Remediation plan",
      "## Annex A — Dismissed candidates",
      "## Annex B — Needs human review",
      "## Annex C — Engines & usage",
    ];
    let at = -1;
    for (const h of order) {
      const i = md.indexOf(h);
      expect(i, h).toBeGreaterThan(at);
      at = i;
    }
  });

  it("each finding card carries area, CWE, OWASP, priority, effort, found-by, scenario and fix", () => {
    n = 0;
    const c = f({ status: "confirmed", severity: "critical", exploitPath: "anyone · sends `' OR 1=1` · gets every row", sources: ["semgrep", "ultrasec"] });
    const narrative: Narrative = {
      remediations: [{ id: c.id, fix: "Use a parameterized query.", patch: "-q('SELECT … ' + id)\n+q('SELECT … ?', [id])", effort: "S" }],
    };
    const md = renderAuditReport(dossier([c]), { narrative });
    expect(md).toContain("area `apps/api`");
    expect(md).toContain("CWE-89");
    expect(md).toContain("OWASP A03 Injection");
    expect(md).toContain("priority **P0**");
    expect(md).toContain("effort S");
    expect(md).toContain("found by semgrep, ultrasec");
    expect(md).toContain("**Attacker scenario:** anyone · sends `' OR 1=1` · gets every row");
    expect(md).toContain("**Fix:** Use a parameterized query.");
    expect(md).toContain("```diff");
    expect(md).toMatch(/### P0 — fix now[\s\S]*Use a parameterized query/);
  });

  it("is not a draft once everything in the code is decided and grounded", () => {
    n = 0;
    const d = dossier([f({ status: "confirmed", severity: "high" }), f({ status: "dismissed", severity: "low" })]);
    expect(reportStatus(d, { ok: true, dangling: 0 }).draft).toBe(false);
    expect(reportStatus(d, { ok: false, dangling: 2 }).reasons.join()).toMatch(/2 cited location\(s\) do not resolve/);
    expect(renderAuditReport(d)).not.toContain("DRAFT");
  });

  it("derives areas from detected workspaces, else the first two path segments", () => {
    expect(areaOf("apps/api/src/x.ts", ["apps/api"])).toBe("apps/api");
    expect(areaOf("services/billing/handler.go", [])).toBe("services/billing");
    expect(areaOf("server.js", [])).toBe("(root)");
  });
});

describe("size discipline", () => {
  it("summarises dismissals by ground and family, listing only the high ones — --full restores every row", () => {
    const d = largeRun();
    const md = renderAuditReport(d);
    const annex = md.slice(md.indexOf("## Annex A"), md.indexOf("## Annex B"));
    expect(annex).toContain("960 candidate(s) dismissed — summarised");
    expect(annex).toMatch(/\| \*\*outside-usage\*\* \| 320 \|/);
    expect(annex).toMatch(/top 15 of 96/);
    expect(annex).not.toContain("argument number 959");
    const full = renderAuditReport(d, { full: true });
    expect(full).toContain("argument number 959");
  });

  it("folds 133 identical confirmed findings into ONE card with the first 10 locations", () => {
    n = 0;
    const d = dossier(Array.from({ length: 133 }, (_, i) => workflow(i, "confirmed")));
    const md = renderAuditReport(d);
    const cards = md.match(/GitHub Action not pinned to a commit SHA/g) ?? [];
    expect(md).toContain("×133");
    expect(md).toContain("_…and 123 more");
    expect(cards.length).toBeLessThan(5);
    expect(renderAuditReport(d, { full: true })).not.toContain("_…and 123 more");
  });

  it("stays well under 300 KB on a 1,245-candidate run (the incident's report was 746 KB)", () => {
    const d = largeRun();
    expect(d.findings.length).toBe(1245);
    const md = renderAuditReport(d);
    const bytes = Buffer.byteLength(md, "utf8");
    expect(bytes).toBeLessThan(300 * 1024);
    // …and the HTML of the same document stays in the same order of magnitude.
    expect(Buffer.byteLength(renderReportHtml(md), "utf8")).toBeLessThan(450 * 1024);
    // --full is the exhaustive form, and is strictly larger.
    expect(Buffer.byteLength(renderAuditReport(d, { full: true }), "utf8")).toBeGreaterThan(bytes);
  });
});

describe("markdown → html", () => {
  it("escapes everything the report quotes, and links only http(s) or in-page anchors", () => {
    const html = markdownToHtml(
      "Engine saw `<script>alert(1)</script>` and [x](javascript:alert(1)) and [ok](https://example.test/a) and [toc](#2-dashboard) <img src=x onerror=alert(1)>",
    );
    expect(html).not.toMatch(/<script|<img|href="javascript/i);
    expect(html).toContain("&lt;script&gt;");
    expect(html).toContain('href="https://example.test/a"');
    expect(html).toContain('href="#2-dashboard"');
  });

  it("renders tables, checklists, quotes and diff blocks", () => {
    const html = markdownToHtml("| a | b |\n|---|---|\n| 1 \\| 2 | 3 |\n\n- [ ] do it\n\n> ## Warn\n> body\n\n```diff\n+add\n-del\n```\n");
    expect(html).toContain("<table>");
    expect(html).toContain("<td>1 | 2</td>");
    expect(html).toContain('<input type="checkbox" disabled>');
    expect(html).toContain('<blockquote class="banner">');
    expect(html).toContain('<span class="add">+add</span>');
  });
});
