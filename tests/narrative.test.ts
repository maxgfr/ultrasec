import { describe, it, expect } from "vitest";
import type { Dossier } from "../src/store.js";
import type { Finding, Narrative } from "../src/types.js";
import { buildNarrativeWorklist, parseNarrative, mergeNarrative, hasNarrativeContent } from "../src/narrative.js";
import { renderSummary, renderReport } from "../src/render/report.js";
import { renderHtml } from "../src/render/html.js";

function f(id: string, status: Finding["status"], severity: Finding["severity"] = "high"): Finding {
  return {
    id,
    category: "taint",
    title: `finding ${id}`,
    severity,
    confidence: "high",
    message: "m",
    tool: "ultrasec",
    status,
    sink: { file: "src/db.js", line: 6 },
  };
}

function dossier(findings: Finding[]): Dossier {
  return {
    manifest: {
      version: "0.0.0",
      schemaVersion: 4,
      repo: "/repo",
      generatedNote: "",
      languages: [],
      toolsRun: [],
      counts: { findings: findings.length, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } },
    },
    findings,
    graph: { files: [], edges: [], symbolDefs: {} },
  };
}

describe("buildNarrativeWorklist", () => {
  it("lists confirmed + needs-human findings and scaffolds a remediation per CONFIRMED one", () => {
    const wl = buildNarrativeWorklist(dossier([f("c1", "confirmed"), f("nh1", "needs-human"), f("o1", "open"), f("d1", "dismissed")]));
    expect(wl.findings.map((x) => x.id).sort()).toEqual(["c1", "nh1"]);
    expect(wl.scaffold.remediations!.map((r) => r.id)).toEqual(["c1"]); // only confirmed gets a fix stub
    expect(wl.scaffold.positivePatterns).toBe(""); // advisory prose stubs are scaffolded too
    expect(wl.scaffold.hardeningNotes).toEqual([]);
  });
});

describe("parseNarrative", () => {
  it("keeps well-formed sections, drops malformed entries", () => {
    const n = parseNarrative(
      JSON.stringify({
        executiveSummary: "Two SQLi were confirmed.",
        positivePatterns: "Auth uses argon2id and every query is parameterized.",
        remediations: [
          { id: "c1", fix: "Use params", owner: "@api" },
          { id: "x", bad: 1 },
        ],
        attackChains: [{ title: "chain", findingIds: ["c1"], narrative: "..." }, { title: "bad" }],
        rootCauses: [{ cause: "string concat", findingIds: ["c1"], note: "n" }],
        hardeningNotes: ["Add a CSP header.", "  ", 42, "Set SameSite=Strict on the session cookie."],
      }),
    );
    expect(n.executiveSummary).toBe("Two SQLi were confirmed.");
    expect(n.positivePatterns).toBe("Auth uses argon2id and every query is parameterized.");
    expect(n.remediations).toHaveLength(1);
    expect(n.attackChains).toHaveLength(1);
    expect(n.rootCauses).toHaveLength(1);
    // non-string / blank hardening notes are dropped, valid ones trimmed
    expect(n.hardeningNotes).toEqual(["Add a CSP header.", "Set SameSite=Strict on the session cookie."]);
  });
});

describe("mergeNarrative — grounding (drops unknown / non-confirmed citations)", () => {
  const d = dossier([f("c1", "confirmed"), f("c2", "confirmed"), f("nh1", "needs-human"), f("d1", "dismissed")]);
  const n: Narrative = {
    executiveSummary: "summary",
    positivePatterns: "argon2id everywhere",
    remediations: [
      { id: "c1", fix: "fix c1" },
      { id: "ghost", fix: "fix ghost" }, // unknown id → dropped
      { id: "nh1", fix: "fix nh1" }, // non-confirmed → dropped
    ],
    attackChains: [
      { title: "valid", findingIds: ["c1", "c2"], narrative: "n" }, // all confirmed → kept
      { title: "touches-dismissed", findingIds: ["c1", "d1"], narrative: "n" }, // cites dismissed → dropped
    ],
    rootCauses: [{ cause: "rc", findingIds: ["c2"], note: "n" }],
    hardeningNotes: ["Add rate limiting at the edge."],
  };
  const merged = mergeNarrative(n, d);

  it("keeps remediation only for confirmed ids", () => {
    expect(merged.remediations!.map((r) => r.id)).toEqual(["c1"]);
  });

  it("drops a chain citing a dismissed finding, keeps an all-confirmed chain", () => {
    expect(merged.attackChains!.map((c) => c.title)).toEqual(["valid"]);
  });

  it("keeps the executive summary and a confirmed-only root cause", () => {
    expect(merged.executiveSummary).toBe("summary");
    expect(merged.rootCauses).toHaveLength(1);
  });

  it("passes advisory prose (positive patterns, hardening notes) through ungrounded — they cite no finding ids", () => {
    expect(merged.positivePatterns).toBe("argon2id everywhere");
    expect(merged.hardeningNotes).toEqual(["Add rate limiting at the edge."]);
  });
});

describe("render — narrative-aware sections appear + are AI-marked", () => {
  const d = dossier([f("c1", "confirmed")]);
  const narrative: Narrative = {
    executiveSummary: "One confirmed SQLi.",
    positivePatterns: "Sessions use HttpOnly+Secure cookies and CSRF tokens.",
    remediations: [{ id: "c1", fix: "Use parameterized queries", owner: "@api", patch: "- bad\n+ good" }],
    attackChains: [{ title: "single hop", findingIds: ["c1"], narrative: "id reaches query()" }],
    rootCauses: [{ cause: "string concat", findingIds: ["c1"], note: "centralize a query builder" }],
    hardeningNotes: ["Add a Content-Security-Policy header."],
  };

  it("SUMMARY gains an AI-marked executive summary + positive patterns", () => {
    const out = renderSummary(d, narrative);
    expect(out).toContain("## Executive summary (AI-authored)");
    expect(out).toContain("One confirmed SQLi.");
    expect(out).toContain("## What the codebase does well (AI-authored)");
    expect(out).toContain("HttpOnly+Secure");
  });

  it("REPORT carries the suggested fix, attack chain, root cause, and hardening notes — all AI-marked", () => {
    const out = renderReport(d, narrative);
    expect(out).toContain("**Suggested fix (AI):** Use parameterized queries · owner @api");
    expect(out).toContain("```diff");
    expect(out).toContain("## Attack chains (AI-authored)");
    expect(out).toContain("## Root-cause groups (AI-authored)");
    expect(out).toContain("## Hardening notes (AI-authored)");
    expect(out).toContain("not** findings"); // hardening notes are clearly NOT findings
    expect(out).toContain("Add a Content-Security-Policy header.");
    expect(out).toContain("verify against the cited findings");
  });

  it("HTML wraps AI content (incl. positive patterns + hardening notes) in .ai-narrative and injects its CSS only when present", () => {
    const withN = renderHtml(d, narrative);
    expect(withN).toContain('class="ai-narrative"');
    expect(withN).toContain(".ai-narrative {"); // CSS injected
    expect(withN).toContain('class="ai-fix"');
    expect(withN).toContain("What the codebase does well");
    expect(withN).toContain("Hardening notes");
    expect(withN).toContain("Add a Content-Security-Policy header.");
    const without = renderHtml(d);
    expect(without).not.toContain("ai-narrative");
    expect(without).not.toContain("ai-fix");
  });
});

describe("hasNarrativeContent", () => {
  it("is false for undefined / empty, true when any section has content", () => {
    expect(hasNarrativeContent(undefined)).toBe(false);
    expect(hasNarrativeContent({})).toBe(false);
    expect(hasNarrativeContent({ executiveSummary: "x" })).toBe(true);
    expect(hasNarrativeContent({ remediations: [{ id: "a", fix: "f" }] })).toBe(true);
    expect(hasNarrativeContent({ positivePatterns: "solid auth" })).toBe(true);
    expect(hasNarrativeContent({ hardeningNotes: ["add a CSP"] })).toBe(true);
  });
});
