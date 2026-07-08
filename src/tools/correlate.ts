import { SEVERITIES, type Confidence, type Finding, type PriorAnalysis, type Severity } from "../types.js";
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
//   • dep (SCA): same package AND they share any advisory id (CVE/GHSA/…) — a
//     single alias hop, scoped to the package, so distinct vulns never merge.
//     Instances across installed VERSIONS / lockfiles collapse into one finding
//     with the per-instance evidence kept in `locations[]` (one advisory on one
//     package = one report entry, not N).
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
  return (f.pkg ?? "").toLowerCase();
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
  const rep = group.slice().sort((a, b) => sevRank(a.severity) - sevRank(b.severity) || (b.risk ?? 0) - (a.risk ?? 0) || byStr(a.id, b.id))[0]!;

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

  // dep clusters can span several installed versions / lockfile paths of the
  // same package — keep every instance as evidence instead of dropping all but
  // the representative's. Only attached when there is more than one distinct
  // instance (the plain same-version cross-tool merge stays field-free).
  if (rep.category === "dep") {
    const byKey = new Map<string, NonNullable<Finding["locations"]>[number]>();
    for (const f of group) {
      const entries = f.locations ?? (f.sink ? [{ file: f.sink.file, line: f.sink.line, ...(f.version ? { version: f.version } : {}) }] : []);
      for (const e of entries) byKey.set(`${e.version ?? ""}|${e.file}|${e.line ?? ""}`, e);
    }
    const locations = [...byKey.entries()].sort((a, b) => byStr(a[0], b[0])).map(([, e]) => e);
    if (locations.length > 1) out.locations = locations;
    else delete out.locations;
  }
  return out;
}

/** Two findings name the same vuln class only when BOTH carry a CWE and they
 *  match (case-insensitive). Absent or differing CWE ⇒ not corroboration: a
 *  standalone finding that merely shares a line with a taint node must NOT fold
 *  into it (that silently destroys a distinct finding + misattributes its verdict). */
function sameCwe(a: string | undefined, b: string | undefined): boolean {
  return !!a && !!b && a.trim().toUpperCase() === b.trim().toUpperCase();
}

/** Every distinct file:line a taint finding touches (source, hops, sink). */
function taintNodes(f: Finding): Set<string> {
  const locs = new Set<string>();
  for (const p of f.path ?? []) locs.add(`${p.file}:${p.line}`);
  if (f.sink) locs.add(`${f.sink.file}:${f.sink.line}`);
  if (f.source) locs.add(`${f.source.file}:${f.source.line}`);
  return locs;
}

/**
 * Collapse corroborating tool findings; then CORROBORATE taint candidates with
 * any standalone tool finding whose exact sink `file:line` lands on a node of the
 * taint path (source/hop/sink). Such a standalone is folded into the taint
 * finding (`sources ∪= tool`, confidence bumped) and CONSUMED — but the taint
 * finding's `path`/`source`/`sink`/`title`/`severity` are NEVER touched (object-
 * copy, exact-line match only, no fuzzy windows). Stable, idempotent (re-running
 * on an already-correlated set is a no-op), order deterministic (id-sorted).
 */
export function correlate(findings: Finding[]): Finding[] {
  const taint = findings.filter((f) => f.tool === "ultrasec");
  const tool = findings.filter((f) => f.tool !== "ultrasec");

  // Correlated (cross-tool de-duplicated) non-taint findings.
  const corr: Finding[] = [];

  // 1) Non-dep: group by category + cwe|title + file:line.
  const nonDep = tool.filter((f) => f.category !== "dep");
  const byKey = new Map<string, Finding[]>();
  for (const f of nonDep) {
    const where = f.sink ? `${f.sink.file}:${f.sink.line}` : "";
    const ident = (f.cwe ?? f.title).trim().toLowerCase();
    const key = `${f.category}::${ident}::${where}`;
    (byKey.get(key) ?? byKey.set(key, []).get(key)!).push(f);
  }
  for (const group of byKey.values()) corr.push(group.length === 1 ? withSources(group[0]!) : mergeCluster(group));

  // 2) dep: union-find over shared advisory ids, scoped to the package.
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
  for (const group of clusters.values()) corr.push(group.length === 1 ? withSources(group[0]!) : mergeCluster(group));

  // 3) Corroborate taint candidates with co-located standalone tool findings.
  const nodesByLoc = new Map<string, number[]>(); // "file:line" -> taint indices
  taint.forEach((t, i) => {
    for (const loc of taintNodes(t)) (nodesByLoc.get(loc) ?? nodesByLoc.set(loc, []).get(loc)!).push(i);
  });
  const extraSources = new Map<number, Set<string>>();
  const extraPrior = new Map<number, PriorAnalysis>(); // carry the consumed finding's signal
  const survivors: Finding[] = [];
  for (const f of corr) {
    const where = f.sink ? `${f.sink.file}:${f.sink.line}` : null;
    const hits = where ? nodesByLoc.get(where) : undefined;
    let corroborated = false;
    if (hits && hits.length) {
      for (const idx of hits) {
        // Co-location is NOT enough: only fold when the standalone is plausibly the
        // SAME vuln class as the taint finding (matching CWE). Otherwise a distinct
        // finding sitting on a shared source/hop/sink line would be silently consumed.
        if (!sameCwe(f.cwe, taint[idx]!.cwe)) continue;
        const set = extraSources.get(idx) ?? extraSources.set(idx, new Set()).get(idx)!;
        for (const s of f.sources ?? [f.tool]) set.add(s);
        // Preserve the standalone's reasoning as a SIGNAL on the taint finding —
        // otherwise corroboration would silently discard it. First one wins.
        if (f.priorAnalysis && !extraPrior.has(idx)) extraPrior.set(idx, f.priorAnalysis);
        corroborated = true;
      }
    }
    if (corroborated) continue; // consumed — it corroborates a taint node, not a standalone finding
    survivors.push(f);
  }
  const taintOut = taint.map((t, i) => {
    const extra = extraSources.get(i);
    if (!extra || !extra.size) return t; // untouched (identity preserved)
    const sources = [...new Set([...(t.sources ?? [t.tool]), ...extra])].sort(byStr);
    const next: Finding = { ...t, sources, confidence: bumpConfidence(t.confidence, sources.length) };
    // Additive only — never touches path/source/sink/title/severity.
    const prior = next.priorAnalysis ?? extraPrior.get(i);
    if (prior) next.priorAnalysis = prior;
    return next;
  });

  return [...taintOut, ...survivors].sort((a, b) => byStr(a.id, b.id));
}

/** Ensure even singletons carry a normalized `sources` list. */
function withSources(f: Finding): Finding {
  return f.sources && f.sources.length ? f : { ...f, sources: [f.tool] };
}
