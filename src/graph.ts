import type { RepoScan } from "./scan.js";
import { enclosingSymbolName } from "./scan.js";
import { buildFileResolver } from "./resolve.js";
import type { WalkedFile } from "./walk.js";
import { langForFile } from "./lang.js";
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

/**
 * Whether two repo files belong to the same language, and so could be in the
 * same call graph at all.
 *
 * `langForFile` returns `undefined` for an extension outside the 15 the engine
 * knows. Two unknowns are treated as NOT the same language: without a language
 * there is no evidence the call is possible, and this gate exists to require
 * evidence.
 */
function sameLanguage(a: string, b: string): boolean {
  const la = langForFile(a)?.id;
  const lb = langForFile(b)?.id;
  return !!la && la === lb;
}

export interface GraphOptions {
  /** A walk of the repo already done by the caller (`scan` shares one across
   *  every pass). The resolver's manifest discovery reads it instead of walking
   *  the tree again. Omitted ⇒ the resolver walks, as before. */
  tree?: readonly WalkedFile[];
}

/** Build the cross-file link-graph (import + resolved call edges). Deterministic. */
export function buildGraph(scan: RepoScan, opts: GraphOptions = {}): Graph {
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
  const resolve = buildFileResolver(scan, opts.tree);

  // Pass 1: import edges only. Call edges need the whole import graph to be
  // known before any of them can be judged (see importReaches), so they wait.
  const importsOf = new Map<string, Set<string>>();
  for (const f of scan.files) {
    for (const imp of f.imports) {
      const to = resolve(f.rel, imp.spec);
      if (!to || to === f.rel) continue;
      add(edgeMap, { from: f.rel, to, kind: "import", weight: 1 });
      let set = importsOf.get(f.rel);
      if (!set) importsOf.set(f.rel, (set = new Set()));
      set.add(to);
    }
  }

  /**
   * Can `from` reach `to` by following imports?
   *
   * A call edge used to need only a unique exported name and a shared language.
   * Uniqueness is not reachability: in a pnpm/lerna monorepo the sole `response`
   * lives in `alert-cli/dares/scrapping.ts`, and every other package calling
   * something named `response` was linked to it — `export-elasticsearch`'s
   * controllers among them, though the two package.json files never name each
   * other. The second audit of that repo counted 21 cross-package paths of this
   * shape, none of them reachable by any runtime.
   *
   * Direct-import equality is too strict to replace it: barrels are ordinary, and
   * a file importing `utils/index.ts` really does call into `utils/name.ts`. So
   * the question asked is transitive over import edges, bounded — deep enough to
   * cross the barrels a package puts in front of itself, not so deep that a
   * monorepo's shared/ tier joins everything to everything.
   *
   * A file whose imports RESOLVED to nothing stays permissive, the rule
   * `requireModule` already follows: absent data means "could not see", not
   * "none". Keying that on resolved edges rather than on written import lines is
   * what makes the gate safe. `pages/api/storage/index.ts` writes five imports —
   * `formidable`, `next`, `fs`, and two `src/lib/...` specifiers that are
   * tsconfig `baseUrl` aliases the resolver does not map — so it has plenty of
   * import lines and zero resolved edges. Judging it on the lines would have cut
   * its real call into `lib/secu.ts:31`, the SVG filter a human audit confirmed.
   * Judging it on the edges keeps it: the engine could not see, so it does not
   * pretend to have looked.
   */
  const IMPORT_REACH_DEPTH = 8;
  const reachCache = new Map<string, Set<string>>();
  const importReaches = (from: string, to: string): boolean => {
    let seen = reachCache.get(from);
    if (!seen) {
      seen = new Set<string>();
      let frontier = [from];
      for (let d = 0; d < IMPORT_REACH_DEPTH && frontier.length; d++) {
        const next: string[] = [];
        for (const node of frontier) {
          for (const nb of importsOf.get(node) ?? []) {
            if (seen.has(nb)) continue;
            seen.add(nb);
            next.push(nb);
          }
        }
        frontier = next;
      }
      reachCache.set(from, seen);
    }
    return seen.has(to);
  };

  // Pass 2: call edges.
  for (const f of scan.files) {
    const blind = (importsOf.get(f.rel)?.size ?? 0) === 0;
    for (const c of f.calls) {
      // Call edges: a call to a uniquely-defined exported symbol in another file.
      const targets = defs.get(c.callee);
      if (!targets || targets.size !== 1) continue; // ambiguous or undefined -> skip
      const to = [...targets][0]!;
      if (to === f.rel) continue; // intra-file call, not a cross-file edge
      // …and it has to be a call the runtime could actually make.
      //
      // `defs` is a global index keyed by NAME ONLY. It does not know which
      // language defined the symbol, so a Python module calling `run(x)` linked
      // to a TypeScript file exporting `run` — and the taint walk then reported
      // a cross-file flow from an `analysis/*.py` source to an `ApiClient.ts`
      // sink. Five such candidates shipped on the first large audit, rated
      // `high`, every one impossible: those two files are not in the same
      // process and neither can call the other.
      //
      // A shared name across languages is a coincidence, not an edge. Where a
      // real cross-language boundary exists it is a subprocess, an HTTP call or
      // an FFI binding — none of which is a `call` edge, and all of which the
      // catalog already models as sinks.
      if (!sameLanguage(f.rel, to)) continue;
      // …and the caller has to be able to reach it. See importReaches.
      if (!blind && !importReaches(f.rel, to)) continue;
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
