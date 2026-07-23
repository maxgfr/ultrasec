import type { RepoScan } from "./scan.js";
import { enclosingSymbolName } from "./scan.js";
import { buildFileResolver } from "./resolve.js";
import { buildRawCallerIndex } from "./vendor/codeindex-engine.mjs";
import { byStr } from "./util.js";

export type EdgeKind = "import" | "call";

export interface Edge {
  from: string; // repo-relative file
  to: string; // repo-relative file
  kind: EdgeKind;
  weight: number;
  /** For call edges: the symbol in `from` issuing the call / the callee in `to`. */
  fromSymbol?: string;
  toSymbol?: string;
}

/** A call site: the file/line issuing a call and its enclosing function. */
export interface CallerRef {
  file: string;
  line: number;
  symbol?: string;
}

export interface Graph {
  files: string[];
  edges: Edge[];
  /** Exported symbol name -> the file(s) that define it. */
  symbolDefs: Record<string, string[]>;
  /**
   * Callee name -> every call site that references it (across ALL files,
   * resolved or not), sorted by (file, line). This is the reverse call-index the
   * taint walk uses to step from a sink back to its callers in O(callers) instead
   * of rescanning every file per BFS frame. Indexed by raw callee name to match
   * the recall-oriented taint walk (which doesn't require a unique definition).
   * Optional so dossiers written before schema v2 still load.
   */
  callersBySymbol?: Record<string, CallerRef[]>;
}

const keyOf = (e: Edge): string => `${e.from}\u0000${e.to}\u0000${e.kind}\u0000${e.toSymbol ?? ""}`;

function add(map: Map<string, Edge>, e: Edge): void {
  const k = keyOf(e);
  const prev = map.get(k);
  if (prev) prev.weight += e.weight;
  else map.set(k, { ...e });
}

/** Build the cross-file link-graph (import + resolved call edges). Deterministic. */
export function buildGraph(scan: RepoScan): Graph {
  const fileSet = new Set(scan.files.map((f) => f.rel));

  // Index unique exported symbol definitions: name -> files defining it.
  const defs = new Map<string, Set<string>>();
  for (const f of scan.files) {
    for (const s of f.symbols) {
      if (!s.exported) continue;
      let set = defs.get(s.name);
      if (!set) defs.set(s.name, (set = new Set()));
      set.add(f.rel);
    }
  }
  const symbolDefs: Record<string, string[]> = {};
  for (const [name, files] of defs) symbolDefs[name] = [...files].sort(byStr);

  const edgeMap = new Map<string, Edge>();
  const resolve = buildFileResolver(scan);

  for (const f of scan.files) {
    // Import edges (resolved to repo files only).
    for (const imp of f.imports) {
      const to = resolve(f.rel, imp.spec);
      if (to && to !== f.rel) add(edgeMap, { from: f.rel, to, kind: "import", weight: 1 });
    }
    for (const c of f.calls) {
      // Call edges: a call to a uniquely-defined exported symbol in another file.
      const targets = defs.get(c.callee);
      if (!targets || targets.size !== 1) continue; // ambiguous or undefined -> skip
      const to = [...targets][0]!;
      if (to === f.rel) continue; // intra-file call, not a cross-file edge
      // The caller attribution uses the SAME endLine-aware enclosing helper the raw
      // caller index uses for its hops (enclosingSymbolName), so a call edge's
      // fromSymbol matches the caller-index site for that same {file, line}.
      const callerSym = enclosingSymbolName(f.symbols, c.line);
      add(edgeMap, { from: f.rel, to, kind: "call", weight: 1, fromSymbol: callerSym, toSymbol: c.callee });
    }
  }

  const edges = [...edgeMap.values()].sort(
    (a, b) => byStr(a.from, b.from) || byStr(a.to, b.to) || byStr(a.kind, b.kind) || byStr(a.toSymbol ?? "", b.toSymbol ?? ""),
  );

  // Reverse call-index straight from the engine's raw caller index (callee name ->
  // every call site, zero gate). Replaces ultrasec's former per-FileScan loop; its
  // enclosing-symbol attribution is endLine-aware and shared with the taint/sink
  // seeds (via enclosingSymbolName), so the BFS steps through one attribution
  // namespace. `symbol` may be undefined when a site is outside every extent.
  const callersBySymbol: Record<string, CallerRef[]> = {};
  if (scan.engine) {
    const raw = buildRawCallerIndex(scan.engine);
    for (const name of [...raw.keys()].sort(byStr)) {
      // Scan-perimeter filter (NOT a resolution gate): buildRawCallerIndex sees every
      // engine-scanned file, including files ultrasec's langForFile gate drops from the
      // RepoScan (a language ultrasec doesn't reason about). Keep only sites in files
      // ultrasec actually scanned, so the caller index's file-set matches the
      // pre-adoption per-FileScan loop's perimeter. Recall is unaffected: a dropped
      // file carries no ultrasec sink/source, so no taint path can traverse it — this
      // narrows the walk surface, it never gates which symbols resolve.
      const refs = raw
        .get(name)!
        .filter((s) => fileSet.has(s.file))
        .map((s): CallerRef => ({ file: s.file, line: s.line, symbol: s.enclosingSymbol?.name }));
      // Keep sorted by (file, line) so the taint BFS visits callers in the same
      // deterministic order the old double loop did (the raw index already sorts;
      // re-sort explicitly after the perimeter filter).
      if (refs.length) callersBySymbol[name] = refs.sort((a, b) => byStr(a.file, b.file) || a.line - b.line);
    }
  }

  return { files: [...fileSet].sort(byStr), edges, symbolDefs, callersBySymbol };
}

const edgeSort = (a: Edge, b: Edge): number => byStr(a.from, b.from) || byStr(a.to, b.to) || byStr(a.kind, b.kind) || byStr(a.toSymbol ?? "", b.toSymbol ?? "");

/** Union two graphs (for merging a scoped pass into an existing run). Deterministic. */
export function mergeGraphs(a: Graph, b: Graph): Graph {
  const files = [...new Set([...a.files, ...b.files])].sort(byStr);

  const edgeMap = new Map<string, Edge>();
  for (const e of [...a.edges, ...b.edges]) {
    const k = keyOf(e);
    const prev = edgeMap.get(k);
    if (prev) prev.weight = Math.max(prev.weight, e.weight);
    else edgeMap.set(k, { ...e });
  }
  const edges = [...edgeMap.values()].sort(edgeSort);

  // Note: symbol names can be Object.prototype members ("toString", "constructor"),
  // so a plain-object lookup by name may return an inherited function — guard with
  // Array.isArray before treating the value as our data.
  const symbolDefs: Record<string, string[]> = {};
  for (const src of [a.symbolDefs, b.symbolDefs]) {
    for (const [name, defFiles] of Object.entries(src)) {
      const prev = Array.isArray(symbolDefs[name]) ? symbolDefs[name]! : [];
      symbolDefs[name] = [...new Set([...prev, ...defFiles])].sort(byStr);
    }
  }

  const callersBySymbol: Record<string, CallerRef[]> = {};
  for (const src of [a.callersBySymbol ?? {}, b.callersBySymbol ?? {}]) {
    for (const [name, refs] of Object.entries(src)) {
      const existing = Array.isArray(callersBySymbol[name]) ? callersBySymbol[name]! : [];
      const seen = new Set(existing.map((r) => `${r.file}:${r.line}:${r.symbol ?? ""}`));
      const merged = [...existing];
      for (const r of refs) {
        const k = `${r.file}:${r.line}:${r.symbol ?? ""}`;
        if (!seen.has(k)) {
          seen.add(k);
          merged.push(r);
        }
      }
      callersBySymbol[name] = merged.sort((x, y) => byStr(x.file, y.file) || x.line - y.line);
    }
  }

  return { files, edges, symbolDefs, callersBySymbol };
}

/**
 * Files that (transitively, up to `depth` hops) depend on or call into any of
 * `seeds` — i.e. the reverse-dependency closure. Used by `--diff` to expand a set
 * of changed files to the call sites that reach them. Includes the seeds. Sorted.
 */
export function reverseDependents(graph: Graph, seeds: string[], depth: number): string[] {
  const inbound = new Map<string, string[]>(); // to -> [from...]
  for (const e of graph.edges) (inbound.get(e.to) ?? inbound.set(e.to, []).get(e.to)!).push(e.from);

  const seen = new Set(seeds);
  let frontier = [...seeds];
  for (let d = 0; d < depth && frontier.length; d++) {
    const next: string[] = [];
    for (const node of frontier) {
      for (const from of inbound.get(node) ?? []) {
        if (seen.has(from)) continue;
        seen.add(from);
        next.push(from);
      }
    }
    frontier = next;
  }
  return [...seen].sort(byStr);
}
