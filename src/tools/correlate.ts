import { SEVERITIES, type Confidence, type Finding, type Severity } from "../types.js";
import { byStr } from "../util.js";
import { pickCve } from "./normalize.js";

// Cross-tool correlation / de-duplication.
//
// The per-tool `makeToolFinding` id embeds the tool name, so the SAME real issue
// reported by trivy + osv + grype yields three distinct ids and three report
// sections. That over-counts and dilutes signal. This collapses corroborating
// findings into one, recording every producer in `sources` — and "N scanners
// agree" becomes a confidence prior for the verify gate.
//
// Two findings are "the same" when:
//   • dep (SCA): same package@version AND they share any advisory id (CVE/GHSA/…)
//     — a single alias hop, scoped to the package, so distinct vulns never merge.
//   • everything else: same category, same CWE-or-title, same file:line.
//
// Engine-enumerated taint candidates (`tool === "ultrasec"`) are left untouched —
// they have unique, meaningful ids and are the AI's to adjudicate.

function sevRank(s: Severity): number {
  return SEVERITIES.indexOf(s);
}
function maxSeverity(a: Severity, b: Severity): Severity {
  return sevRank(a) <= sevRank(b) ? a : b;
}

function pkgKey(f: Finding): string {
  return `${(f.pkg ?? "").toLowerCase()}@${(f.version ?? "").toLowerCase()}`;
}

/** All advisory ids a dep finding is known by (for the shared-id test). */
function depIds(f: Finding): string[] {
  const ids = new Set<string>();
  if (f.cve) ids.add(f.cve.toUpperCase());
  for (const a of f.aliases ?? []) ids.add(a.toUpperCase());
  if (!ids.size) ids.add(f.title.toUpperCase()); // last resort: title identity
  return [...ids];
}

// ── Tiny union-find over finding indices ────────────────────────────────────
class DSU {
  private p: number[];
  constructor(n: number) {
    this.p = Array.from({ length: n }, (_, i) => i);
  }
  find(x: number): number {
    while (this.p[x] !== x) x = this.p[x] = this.p[this.p[x]!]!;
    return x;
  }
  union(a: number, b: number): void {
    this.p[this.find(a)] = this.find(b);
  }
}

function bumpConfidence(c: Confidence, agree: number): Confidence {
  // ≥2 independent tools flagging the same thing → corroborated → high.
  return agree >= 2 ? "high" : c;
}

/** Merge a cluster of equivalent findings into one representative. */
function mergeCluster(group: Finding[]): Finding {
  // Representative = most severe, then highest pre-existing risk, then stable id.
  const rep = group.slice().sort(
    (a, b) => sevRank(a.severity) - sevRank(b.severity) || (b.risk ?? 0) - (a.risk ?? 0) || byStr(a.id, b.id),
  )[0]!;

  const sources = [...new Set(group.flatMap((f) => f.sources ?? [f.tool]))].sort(byStr);
  const references = [...new Set(group.flatMap((f) => f.references ?? []))];
  const aliases = [...new Set(group.flatMap((f) => f.aliases ?? []).map((a) => a.toUpperCase()))].sort(byStr);
  const severity = group.reduce<Severity>((s, f) => maxSeverity(s, f.severity), "info");
  const cve = group.map((f) => f.cve).find(Boolean) ?? pickCve(aliases);
  const cwe = group.map((f) => f.cwe).find(Boolean);
  const verified = group.some((f) => f.verified === true);

  const out: Finding = {
    ...rep,
    severity,
    sources,
    confidence: bumpConfidence(rep.confidence, sources.length),
  };
  if (references.length) out.references = references;
  else delete out.references;
  if (aliases.length) out.aliases = aliases;
  if (cve) out.cve = cve;
  if (cwe) out.cwe = cwe;
  if (verified) out.verified = true;
  return out;
}

/**
 * Collapse corroborating tool findings; leave taint candidates as-is. Stable,
 * idempotent (re-running on an already-correlated set is a no-op), and order is
 * deterministic (id-sorted).
 */
export function correlate(findings: Finding[]): Finding[] {
  const taint = findings.filter((f) => f.tool === "ultrasec");
  const tool = findings.filter((f) => f.tool !== "ultrasec");

  const out: Finding[] = [...taint];

  // 1) Non-dep: group by category + cwe|title + file:line.
  const nonDep = tool.filter((f) => f.category !== "dep");
  const byKey = new Map<string, Finding[]>();
  for (const f of nonDep) {
    const where = f.sink ? `${f.sink.file}:${f.sink.line}` : "";
    const ident = (f.cwe ?? f.title).trim().toLowerCase();
    const key = `${f.category}::${ident}::${where}`;
    (byKey.get(key) ?? byKey.set(key, []).get(key)!).push(f);
  }
  for (const group of byKey.values()) out.push(group.length === 1 ? withSources(group[0]!) : mergeCluster(group));

  // 2) dep: union-find over shared advisory ids, scoped to package@version.
  const dep = tool.filter((f) => f.category === "dep");
  const dsu = new DSU(dep.length);
  const seen = new Map<string, number>(); // "pkgKey|ID" -> first finding index
  dep.forEach((f, i) => {
    const pk = pkgKey(f);
    for (const id of depIds(f)) {
      const k = `${pk}|${id}`;
      const prev = seen.get(k);
      if (prev === undefined) seen.set(k, i);
      else dsu.union(prev, i);
    }
  });
  const clusters = new Map<number, Finding[]>();
  dep.forEach((f, i) => {
    const r = dsu.find(i);
    (clusters.get(r) ?? clusters.set(r, []).get(r)!).push(f);
  });
  for (const group of clusters.values()) out.push(group.length === 1 ? withSources(group[0]!) : mergeCluster(group));

  return out.sort((a, b) => byStr(a.id, b.id));
}

/** Ensure even singletons carry a normalized `sources` list. */
function withSources(f: Finding): Finding {
  return f.sources && f.sources.length ? f : { ...f, sources: [f.tool] };
}
