import { describe, it, expect } from "vitest";
import { compareFindings, rankScore, sortFindings, statusRank } from "../src/rank.js";
import { groupFamilies, pathRoot, collapsedCount } from "../src/family.js";
import type { Finding, Severity, Status } from "../src/types.js";

// The ranking and folding rules, pinned against the audit that produced them.
//
// Measured on a 1366-finding run of a real monorepo: the first fifteen entries
// by rank were thirteen REFUTED candidates, the three confirmed criticals sat at
// ranks 1343-1366, and four repeated scanner titles accounted for 604 rows.

const f = (over: Partial<Finding> & { id: string }): Finding => ({
  category: "sast",
  title: "t",
  severity: "medium",
  confidence: "low",
  message: "m",
  tool: "ultrasec",
  status: "open",
  ...over,
});

const at = (file: string, line = 1) => ({ sink: { file, line } });

describe("rank — the audit's decisions order the report", () => {
  it("puts a confirmed finding above a refuted one, whatever the risk scores say", () => {
    // The exact shape of the bug: a refuted candidate carrying a high engine
    // risk outranked a confirmed finding that carried none.
    const refuted = f({ id: "refuted", status: "dismissed", risk: 95, severity: "critical" });
    const confirmed = f({ id: "confirmed", status: "confirmed", severity: "high" });
    expect(sortFindings([refuted, confirmed]).map((x) => x.id)).toEqual(["confirmed", "refuted"]);
  });

  it("orders confirmed → needs-human → open → dismissed", () => {
    const order: Status[] = ["dismissed", "open", "needs-human", "confirmed"];
    const findings = order.map((status, i) => f({ id: String(i), status }));
    expect(sortFindings(findings).map((x) => x.status)).toEqual(["confirmed", "needs-human", "open", "dismissed"]);
  });

  it("ranks an UNSCORED finding by its severity, not below everything", () => {
    // `risk` is attached during `scan`, so anything ingested later has none.
    // Reading that as -1 buried every agent-authored finding — including, on the
    // real run, all three confirmed criticals.
    const scored = f({ id: "scored", status: "confirmed", severity: "low", risk: 20 });
    const unscored = f({ id: "unscored", status: "confirmed", severity: "critical" });
    expect(sortFindings([scored, unscored]).map((x) => x.id)).toEqual(["unscored", "scored"]);
    expect(rankScore(unscored)).toBe(60); // the severity-only branch of riskScore
    expect(rankScore(scored)).toBe(20); // an explicit score always wins
  });

  it("sorts a malformed severity LAST rather than above every critical", () => {
    const broken = f({ id: "broken", severity: null as unknown as Severity });
    const crit = f({ id: "crit", severity: "critical" });
    expect(sortFindings([broken, crit]).map((x) => x.id)).toEqual(["crit", "broken"]);
  });

  it("is deterministic — equal findings break the tie on id", () => {
    const a = f({ id: "aaa", risk: 50 });
    const b = f({ id: "bbb", risk: 50 });
    expect(compareFindings(a, b)).toBeLessThan(0);
    expect(compareFindings(b, a)).toBeGreaterThan(0);
  });

  it("treats an absent status as undone, not as archived", () => {
    expect(statusRank(undefined)).toBe(statusRank("open"));
  });
});

describe("family — a repetition is one judgment, not N", () => {
  it("groups by title AND path root, so a monorepo's components stay apart", () => {
    const findings = [
      ...[1, 2, 3].map((i) => f({ id: `a${i}`, title: "B301 blacklist", ...at(`analysis/.venv/x${i}.py`) })),
      ...[1, 2, 3].map((i) => f({ id: `b${i}`, title: "B301 blacklist", ...at(`targets/frontend/y${i}.py`) })),
    ];
    const { families } = groupFamilies(findings);
    expect(families).toHaveLength(2);
    expect(families.map((x) => x.root).sort()).toEqual(["analysis/.venv", "targets/frontend"]);
    expect(collapsedCount(groupFamilies(findings))).toBe(4); // 6 findings → 2 leads
  });

  it("leaves a pair alone — the fold starts paying off at three", () => {
    const findings = [1, 2].map((i) => f({ id: `p${i}`, title: "same", ...at(`src/x${i}.js`) }));
    const g = groupFamilies(findings);
    expect(g.families).toHaveLength(0);
    expect(g.singles).toHaveLength(2);
  });

  it("never merges members — every finding is still individually addressable", () => {
    const findings = [1, 2, 3, 4].map((i) => f({ id: `m${i}`, title: "same", ...at(`src/x${i}.js`) }));
    const { families } = groupFamilies(findings);
    expect(families[0]!.members.map((m) => m.id).sort()).toEqual(["m1", "m2", "m3", "m4"]);
    expect(families[0]!.members).toContain(families[0]!.lead);
  });

  it("does not put two distinct CVEs in one family because they cite the same lockfile line", () => {
    const findings = [1, 2, 3].map((i) => f({ id: `cve${i}`, category: "dep", title: `CVE-2026-000${i}`, ...at("pnpm-lock.yaml") }));
    expect(groupFamilies(findings).families).toHaveLength(0);
  });

  it("keys a monorepo path on two segments and a flat one on what it has", () => {
    expect(pathRoot("targets/frontend/src/pages/api/x.ts")).toBe("targets/frontend");
    expect(pathRoot("src/x.ts")).toBe("src");
    expect(pathRoot("README.md")).toBe(".");
  });
});

// ── Compaction must not be lossy ───────────────────────────────────────────
//
// The first cut of the compact tiers showed only the named ground (`brocard`)
// and dropped the auditor's argument, which lives appended to `message` as
// "Verdict (refuted): …". Measured on a real run: 1041 refuted findings carried
// **384 distinct arguments**, and 38 of 69 families mixed different ones under a
// single exemplar. A tier printed so its refutations can be checked, minus the
// reasoning, is not checkable.

import { renderReport } from "../src/render/report.js";
import { renderHtml } from "../src/render/html.js";
import type { Dossier } from "../src/store.js";

const REFUTED_BECAUSE = "the cited value is a literal, never attacker-controlled";

const dossierOf = (findings: Finding[]): Dossier => ({
  manifest: {
    version: "0.0.0-test",
    schema: 9,
    repo: "/tmp/repo",
    generatedNote: "test",
    languages: [],
    toolsRun: [],
    counts: { findings: findings.length, bySeverity: { critical: 0, high: 0, medium: findings.length, low: 0, info: 0 } },
  } as unknown as Dossier["manifest"],
  findings,
  graph: { files: [], edges: [], symbolDefs: {} },
});

describe("compaction keeps the judgment and drops only the mechanical", () => {
  const refuted = (id: string, file: string): Finding =>
    f({
      id,
      status: "dismissed",
      verdict: "refuted",
      brocard: "standard-behavior",
      title: "Log injection: untrusted input reaches info()",
      message: `Engine boilerplate about the candidate.\n\nVerdict (refuted): ${REFUTED_BECAUSE}`,
      ...at(file),
    });

  const findings = [refuted("r1", "src/a.js"), refuted("r2", "src/b.js"), refuted("r3", "src/c.js")];

  it("prints the refutation ARGUMENT in the compact Markdown tier, not just the ground", () => {
    const md = renderReport(dossierOf(findings));
    expect(md).toContain("standard-behavior");
    expect(md, "the reasoning that decided the audit must survive compaction").toContain(REFUTED_BECAUSE);
  });

  it("prints it in the compact HTML tier too", () => {
    const html = renderHtml(dossierOf(findings));
    expect(html).toContain(REFUTED_BECAUSE);
  });

  it("never folds two DIFFERENT judgments into one family", () => {
    const mixed = [
      refuted("m1", "src/a.js"),
      refuted("m2", "src/b.js"),
      f({
        id: "m3",
        status: "dismissed",
        verdict: "refuted",
        title: "Log injection: untrusted input reaches info()",
        message: "Engine boilerplate.\n\nVerdict (refuted): a completely different reason",
        ...at("src/c.js"),
      }),
    ];
    // Same title, same path root — but not the same judgment, so not one family.
    expect(groupFamilies(mixed).families).toHaveLength(0);
    const md = renderReport(dossierOf(mixed));
    expect(md).toContain(REFUTED_BECAUSE);
    expect(md).toContain("a completely different reason");
  });

  it("folds findings that DO share a judgment, and says the adjudication is shared", () => {
    const { families } = groupFamilies(findings);
    expect(families).toHaveLength(1);
    expect(families[0]!.note).toContain(REFUTED_BECAUSE);
    expect(families[0]!.members).toHaveLength(3);
  });
});
