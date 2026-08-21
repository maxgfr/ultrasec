import { describe, it, expect } from "vitest";
import type { Dossier } from "../src/store.js";
import type { Finding, Severity } from "../src/types.js";
import { buildWorklist, shard, applyVerdicts, parseVerdicts, renderWorklistMd, worklistCounts } from "../src/verify.js";

function finding(id: string, severity: Severity, status: Finding["status"] = "open"): Finding {
  return {
    id,
    category: "taint",
    cwe: "CWE-89",
    title: `finding ${id}`,
    severity,
    confidence: "low",
    message: "candidate",
    tool: "ultrasec",
    status,
    sink: { file: "src/db.js", line: 6 },
    path: [
      { file: "src/server.js", line: 10, why: "source" },
      { file: "src/db.js", line: 6, why: "sink" },
    ],
  };
}

function dossier(findings: Finding[]): Dossier {
  return {
    manifest: {
      version: "0.0.0",
      schemaVersion: 1,
      repo: "/repo",
      generatedNote: "",
      languages: ["javascript"],
      toolsRun: [],
      counts: { findings: findings.length, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } },
    },
    findings,
    graph: { files: [], edges: [], symbolDefs: {} },
  };
}

describe("buildWorklist", () => {
  it("includes open + needs-human, excludes confirmed/dismissed", () => {
    const d = dossier([finding("a", "high"), finding("b", "high", "confirmed"), finding("c", "high", "needs-human"), finding("d", "high", "dismissed")]);
    expect(buildWorklist(d).map((i) => i.id)).toEqual(["a", "c"]);
  });
});

describe("shard", () => {
  it("round-robins into disjoint balanced slices covering everything", () => {
    const items = [1, 2, 3, 4, 5];
    const s0 = shard(items, 2, 0);
    const s1 = shard(items, 2, 1);
    expect(s0).toEqual([1, 3, 5]);
    expect(s1).toEqual([2, 4]);
    expect([...s0, ...s1].sort()).toEqual(items);
  });
});

describe("buildWorklist — delta by default", () => {
  // A needs-human finding that already carries a verdict was READ and escalated
  // by someone. One without a verdict was escalated by another stage and has
  // never been ruled on — so it is still new work.
  function adjudicated(id: string): Finding {
    return { ...finding(id, "high", "needs-human"), verdict: "partial" };
  }

  it("withholds findings an earlier pass already adjudicated", () => {
    const d = dossier([finding("a", "high"), adjudicated("b"), finding("c", "high", "needs-human")]);
    expect(buildWorklist(d).map((i) => i.id)).toEqual(["a", "c"]);
    expect(worklistCounts(d)).toEqual({ fresh: 2, reOpened: 0, withheld: 1 });
  });

  it("--all re-opens them, carrying the prior verdict so they read as not-new", () => {
    const d = dossier([finding("a", "high"), adjudicated("b")]);
    const items = buildWorklist(d, { all: true });
    expect(items.map((i) => i.id)).toEqual(["a", "b"]);
    expect(items.find((i) => i.id === "b")!.priorVerdict).toBe("partial");
    expect(items.find((i) => i.id === "a")!.priorVerdict).toBeUndefined();
    expect(worklistCounts(d, { all: true })).toEqual({ fresh: 1, reOpened: 1, withheld: 0 });
  });

  it("the brief names what was withheld and the flag that shows it", () => {
    const d = dossier([finding("a", "high"), adjudicated("b")]);
    const md = renderWorklistMd(buildWorklist(d), undefined, worklistCounts(d));
    expect(md).toContain("1 already adjudicated as needs-human and NOT shown");
    expect(md).toContain("--all");
  });

  it("says nothing extra when there is nothing withheld (output unchanged)", () => {
    const d = dossier([finding("a", "high")]);
    const md = renderWorklistMd(buildWorklist(d), undefined, worklistCounts(d));
    expect(md).not.toContain("--all");
    expect(md).toBe(renderWorklistMd(buildWorklist(d)));
  });
});

describe("applyVerdicts — re-verdict guardrail", () => {
  it("reports a verdict that CHANGES an already-adjudicated finding", () => {
    const prev = { ...finding("a", "high", "dismissed"), verdict: "refuted" as const };
    const r = applyVerdicts(dossier([prev]), [{ id: "a", verdict: "supported" }]);
    expect(r.reVerdicted).toEqual([{ id: "a", from: "refuted", to: "supported", wasStatus: "dismissed" }]);
  });

  it("stays quiet when the same verdict is re-applied (idempotent re-fold)", () => {
    const prev = { ...finding("a", "high", "dismissed"), verdict: "refuted" as const };
    expect(applyVerdicts(dossier([prev]), [{ id: "a", verdict: "refuted" }]).reVerdicted).toEqual([]);
  });

  it("stays quiet on a genuinely open finding — first adjudication is not a re-verdict", () => {
    expect(applyVerdicts(dossier([finding("a", "high")]), [{ id: "a", verdict: "refuted" }]).reVerdicted).toEqual([]);
  });

  it("still APPLIES the change — this reports, it does not block", () => {
    const prev = { ...finding("a", "high", "dismissed"), verdict: "refuted" as const };
    const r = applyVerdicts(dossier([prev]), [{ id: "a", verdict: "supported" }]);
    expect(r.findings[0]!.status).toBe("confirmed");
  });
});

describe("applyVerdicts — conservative policy", () => {
  it("supported → confirmed (confidence raised)", () => {
    const r = applyVerdicts(dossier([finding("a", "high")]), [{ id: "a", verdict: "supported", exploitPath: "POST /x" }]);
    expect(r.findings[0]!.status).toBe("confirmed");
    expect(r.findings[0]!.confidence).toBe("high");
    expect(r.findings[0]!.exploitPath).toBe("POST /x");
    expect(r.confirmed).toBe(1);
  });

  it("refuted → dismissed (explicit contradiction is safe to drop)", () => {
    const r = applyVerdicts(dossier([finding("a", "critical")]), [{ id: "a", verdict: "refuted" }]);
    expect(r.findings[0]!.status).toBe("dismissed");
  });

  it("unsupported on a HIGH finding → needs-human, NOT dismissed", () => {
    const r = applyVerdicts(dossier([finding("a", "high")]), [{ id: "a", verdict: "unsupported" }]);
    expect(r.findings[0]!.status).toBe("needs-human");
    expect(r.keptForHuman).toHaveLength(1);
  });

  it("unsupported on a LOW finding → dismissed", () => {
    const r = applyVerdicts(dossier([finding("a", "low")]), [{ id: "a", verdict: "unsupported" }]);
    expect(r.findings[0]!.status).toBe("dismissed");
  });

  it("partial → needs-human", () => {
    const r = applyVerdicts(dossier([finding("a", "medium")]), [{ id: "a", verdict: "partial" }]);
    expect(r.findings[0]!.status).toBe("needs-human");
  });
});

describe("applyVerdicts — idempotent message folding", () => {
  // Applying the same verdicts file twice used to append a second
  // "Verdict (...)" block every time. On a real run all 265 findings carried a
  // duplicate and one carried four, which is what inflated REPORT.md.
  it("re-applying the same verdict leaves the message byte-identical", () => {
    const rows = [{ id: "a", verdict: "refuted" as const, note: "test-only path" }];
    const once = applyVerdicts(dossier([finding("a", "high")]), rows);
    const twice = applyVerdicts({ ...dossier([]), findings: once.findings }, rows);
    expect(twice.findings[0]!.message).toBe(once.findings[0]!.message);
    expect(twice.findings[0]!.message.match(/\n\nVerdict \(/g)).toHaveLength(1);
  });

  it("a CHANGED verdict replaces the previous block instead of stacking", () => {
    const first = applyVerdicts(dossier([finding("a", "high")]), [{ id: "a", verdict: "refuted", note: "first" }]);
    const second = applyVerdicts({ ...dossier([]), findings: first.findings }, [{ id: "a", verdict: "supported", note: "second" }]);
    const msg = second.findings[0]!.message;
    expect(msg.match(/\n\nVerdict \(/g)).toHaveLength(1);
    expect(msg).toContain("Verdict (supported): second");
    expect(msg).not.toContain("first");
    expect(msg.startsWith("candidate")).toBe(true);
  });

  it("preserves another stage's note — a revalidation survives a re-verify", () => {
    const f = finding("a", "high");
    f.message = "candidate\n\nRevalidation (still-valid): re-confirmed at HEAD";
    const r = applyVerdicts(dossier([f]), [{ id: "a", verdict: "refuted", note: "ground" }]);
    expect(r.findings[0]!.message).toContain("Revalidation (still-valid): re-confirmed at HEAD");
    expect(r.findings[0]!.message).toContain("Verdict (refuted): ground");
  });
});

describe("priorAnalysis signal (deepsec revalidation) — shown, never auto-applied", () => {
  function withPrior(): Finding {
    const f = finding("a", "high");
    f.priorAnalysis = { tool: "deepsec", revalidationVerdict: "true-positive", reasoning: "reaches the DB unsanitized" };
    return f;
  }

  it("surfaces the revalidation verdict as a labelled signal in the worklist + MD", () => {
    const d = dossier([withPrior()]);
    const item = buildWorklist(d)[0]!;
    expect(item.priorSignal).toBe("deepsec revalidation: true-positive");
    expect(renderWorklistMd(buildWorklist(d))).toContain("signal (not a verdict — adjudicate yourself): deepsec revalidation: true-positive");
  });

  it("does NOT change status: a finding with a 'true-positive' signal stays open until verified", () => {
    const r = applyVerdicts(dossier([withPrior()]), []); // no verdict supplied
    expect(r.findings[0]!.status).toBe("open");
    expect(r.applied).toBe(0);
  });

  it("items without priorAnalysis carry no signal (back-compat)", () => {
    expect(buildWorklist(dossier([finding("b", "high")]))[0]!.priorSignal).toBeUndefined();
  });
});

describe("parseVerdicts", () => {
  it("accepts a bare array and a {verdicts:[]} wrapper, dropping malformed", () => {
    const out = parseVerdicts('[{"id":"a","verdict":"supported"},{"bad":1}]');
    expect(out.rows).toEqual([{ id: "a", verdict: "supported", note: undefined, exploitPath: undefined }]);
    expect(out.dropped).toHaveLength(1);
    expect(out.dropped[0]!.reason).toMatch(/id missing.*verdict missing/);
    expect(parseVerdicts('{"verdicts":[{"id":"b","verdict":"refuted"}]}').rows[0]!.id).toBe("b");
  });

  it("fails closed on an unrecognized container shape instead of yielding 0 rows", () => {
    expect(() => parseVerdicts('{"pairs":[{"id":"a","verdict":"supported"}]}')).toThrow(/expected a JSON array/i);
  });

  it("fails closed when rows exist but none are usable", () => {
    expect(() => parseVerdicts('[{"id":"a","verdict":"INVALID"},{"bad":1}]')).toThrow(/none usable/i);
  });

  it("still accepts a genuinely empty array (a no-op fragment)", () => {
    expect(parseVerdicts("[]")).toEqual({ rows: [], dropped: [] });
  });
});

describe("applyVerdicts — stale ids", () => {
  it("reports verdicts targeting unknown ids as ignored, folding the known ones", () => {
    const r = applyVerdicts(dossier([finding("a", "high")]), [
      { id: "a", verdict: "supported" },
      { id: "ghost", verdict: "refuted" },
    ]);
    expect(r.applied).toBe(1);
    expect(r.ignored).toEqual(["ghost"]);
    expect(r.findings[0]!.status).toBe("confirmed");
  });

  it("ignored is empty when every id resolves", () => {
    expect(applyVerdicts(dossier([finding("a", "high")]), [{ id: "a", verdict: "partial" }]).ignored).toEqual([]);
  });
});
