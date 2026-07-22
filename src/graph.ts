import type { RepoScan } from "./scan.js";
import { buildFileResolver } from "./resolve.js";
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

// Which line/symbol encloses a given line — used to attribute a call to its
// caller function. Returns the nearest preceding symbol definition.
function enclosingSymbol(symbols: { name: string; line: number }[], line: number): string | undefined {
  let best: { name: string; line: number } | undefined;
  for (const s of symbols) {
    if (s.line <= line && (!best || s.line > best.line)) best = s;
  }
  return best?.name;
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
  const callers = new Map<string, CallerRef[]>();
  const resolve = buildFileResolver(scan);

  for (const f of scan.files) {
    // Import edges (resolved to repo files only).
    for (const imp of f.imports) {
      const to = resolve(f.rel, imp.spec);
      if (to && to !== f.rel) add(edgeMap, { from: f.rel, to, kind: "import", weight: 1 });
    }
    for (const c of f.calls) {
      const callerSym = enclosingSymbol(f.symbols, c.line);
      // Reverse call-index: record EVERY call site keyed by callee name (this is
      // what the taint walk steps through, so it must mirror the old per-file scan).
      (callers.get(c.callee) ?? callers.set(c.callee, []).get(c.callee)!).push({ file: f.rel, line: c.line, symbol: callerSym });
      // Call edges: a call to a uniquely-defined exported symbol in another file.
      const targets = defs.get(c.callee);
      if (!targets || targets.size !== 1) continue; // ambiguous or undefined -> skip
      const to = [...targets][0]!;
      if (to === f.rel) continue; // intra-file call, not a cross-file edge
      add(edgeMap, { from: f.rel, to, kind: "call", weight: 1, fromSymbol: callerSym, toSymbol: c.callee });
    }
  }

  const edges = [...edgeMap.values()].sort(
    (a, b) => byStr(a.from, b.from) || byStr(a.to, b.to) || byStr(a.kind, b.kind) || byStr(a.toSymbol ?? "", b.toSymbol ?? ""),
  );

  // Sort each caller list by (file, line) so the taint BFS visits callers in the
  // same order the old `scan.files × calls` double loop did — keeps output identical.
  const callersBySymbol: Record<string, CallerRef[]> = {};
  for (const [name, refs] of [...callers.entries()].sort((a, b) => byStr(a[0], b[0]))) {
    callersBySymbol[name] = refs.sort((a, b) => byStr(a.file, b.file) || a.line - b.line);
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
