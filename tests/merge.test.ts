import { describe, it, expect } from "vitest";
import { mergeDossier, countBySeverity, type Dossier } from "../src/store.js";
import type { Finding, Manifest } from "../src/types.js";
import type { Graph } from "../src/graph.js";

const emptyGraph = (files: string[] = []): Graph => ({ files, edges: [], symbolDefs: {}, callersBySymbol: {} });

function finding(id: string, over: Partial<Finding> = {}): Finding {
  return {
    id,
    category: "taint",
    title: `finding ${id}`,
    severity: "high",
    confidence: "low",
    message: "candidate",
    tool: "ultrasec",
    status: "open",
    ...over,
  };
}

function dossier(findings: Finding[], scopes?: string[]): Dossier {
  const manifest: Manifest = {
    version: "x",
    schemaVersion: 2,
    repo: "/r",
    generatedNote: "",
    languages: ["javascript"],
    toolsRun: [],
    counts: { findings: findings.length, bySeverity: countBySeverity(findings) },
    ...(scopes ? { scopes } : {}),
  };
  return { manifest, findings, graph: emptyGraph(findings.flatMap((f) => (f.sink ? [f.sink.file] : []))) };
}

describe("mergeDossier", () => {
  it("preserves a confirmed verdict across a scoped re-scan", () => {
    const prev = dossier([finding("a", { status: "confirmed", verdict: "supported", confidence: "high", exploitPath: "GET /x", message: "candidate\n\nVerdict (supported): real" })]);
    // the same finding re-enumerated by a scoped pass arrives as fresh `open`
    const next = dossier([finding("a", { status: "open", confidence: "low", message: "candidate" })], ["src"]);
    const merged = mergeDossier(prev, next);
    const a = merged.findings.find((f) => f.id === "a")!;
    expect(a.status).toBe("confirmed");
    expect(a.verdict).toBe("supported");
    expect(a.exploitPath).toBe("GET /x");
    expect(a.message).toContain("Verdict (supported)");
  });

  it("appends genuinely new findings", () => {
    const prev = dossier([finding("a")]);
    const next = dossier([finding("b", { severity: "critical" })], ["src/api"]);
    const merged = mergeDossier(prev, next);
    expect(merged.findings.map((f) => f.id).sort()).toEqual(["a", "b"]);
    expect(merged.manifest.counts.findings).toBe(2);
  });

  it("keeps findings outside the current pass's scope (does not delete them)", () => {
    const prev = dossier([finding("a", { status: "confirmed" }), finding("b", { status: "dismissed" })]);
    const next = dossier([finding("a", { status: "open" })], ["src"]); // only re-scanned 'a'
    const merged = mergeDossier(prev, next);
    expect(merged.findings.map((f) => f.id).sort()).toEqual(["a", "b"]); // 'b' survives
    expect(merged.findings.find((f) => f.id === "b")!.status).toBe("dismissed");
  });

  it("a SCOPED merge carries a prior cap forward (must not hide a capped run)", () => {
    const prev = dossier([finding("a")]);
    prev.manifest.truncation = { candidates: 3400, total: 4400 };
    const next = dossier([finding("a")], ["src"]); // scoped pass, NOT truncated
    const merged = mergeDossier(prev, next);
    expect(merged.manifest.truncation).toBeTruthy();
    expect(merged.manifest.truncation!.candidates).toBe(3400);
    expect(merged.manifest.truncation!.total).toBe(4400);
  });

  it("a FULL uncapped re-scan CLEARS a stale prior cap (no false truncation warning)", () => {
    const prev = dossier([finding("a")]);
    prev.manifest.truncation = { candidates: 3400, total: 4400 };
    const next = dossier([finding("a")]); // full re-scan (no scopes), not truncated
    const merged = mergeDossier(prev, next);
    expect(merged.manifest.truncation).toBeUndefined(); // stale cap cleared
  });

  it("unions scopes and is idempotent", () => {
    const prev = dossier([finding("a")], ["src"]);
    const next = dossier([finding("a")], ["lib"]);
    const merged = mergeDossier(prev, next);
    expect(merged.manifest.scopes).toEqual(["lib", "src"]);
    expect(mergeDossier(merged, merged).findings).toEqual(merged.findings);
  });
});
