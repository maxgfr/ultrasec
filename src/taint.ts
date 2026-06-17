import { join } from "node:path";
import { readText } from "./walk.js";
import type { RepoScan, FileScan } from "./scan.js";
import type { Graph } from "./graph.js";
import { langForFile } from "./lang.js";
import { findSinks, findSources, findSanitizers, cweUrl, type SinkHit, type SourceHit } from "./catalog.js";
import { shortHash, byStr } from "./util.js";
import { SEVERITIES, type Finding, type PathStep, type Severity } from "./types.js";

const DEFAULT_MAX_DEPTH = 6; // call-graph hops walked back from a sink
const DEFAULT_MAX_CANDIDATES = 1000;

export interface TaintOptions {
  /** Call-graph hops walked back from each sink (default 6). */
  maxDepth?: number;
  /** Keep at most this many ranked candidates (default 1000). Excess is reported, not dropped silently. */
  maxCandidates?: number;
}

export interface TaintResult {
  findings: Finding[];
  /** Candidates dropped by `maxCandidates` (0 = none). */
  truncated: number;
  /** Total candidates enumerated before the cap. */
  total: number;
}

function severityRank(s: Severity): number {
  return SEVERITIES.indexOf(s); // 0 = critical … 4 = info
}

/** Nearest preceding symbol definition — attributes a line to its function. */
function enclosingSymbol(file: FileScan, line: number): string | undefined {
  let best: { name: string; line: number } | undefined;
  for (const s of file.symbols) {
    if (s.line <= line && (!best || s.line > best.line)) best = s;
  }
  return best?.name;
}

function truncate(s: string, n = 60): string {
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

/**
 * Enumerate candidate cross-file source→sink taint paths. Summary-based and
 * recall-oriented: for each dangerous sink, walk the call-graph backwards to any
 * file carrying untrusted input and emit the chain as a low-confidence candidate
 * for the AI to adjudicate (it is the AI that confirms reachability/exploitability
 * and raises confidence via the verify gate).
 */
export function enumerateTaint(scan: RepoScan, graph: Graph, opts: TaintOptions = {}): TaintResult {
  const MAX_DEPTH = opts.maxDepth ?? DEFAULT_MAX_DEPTH;
  const maxCandidates = opts.maxCandidates ?? DEFAULT_MAX_CANDIDATES;
  const byRel = new Map(scan.files.map((f) => [f.rel, f]));
  const contentCache = new Map<string, string>();
  const sourceCache = new Map<string, SourceHit[]>();
  const lineCache = new Map<string, string[]>();

  const content = (rel: string): string => {
    let c = contentCache.get(rel);
    if (c === undefined) contentCache.set(rel, (c = readText(join(scan.repo, rel))));
    return c;
  };
  const lines = (rel: string): string[] => {
    let l = lineCache.get(rel);
    if (!l) lineCache.set(rel, (l = content(rel).split(/\r?\n/)));
    return l;
  };
  const sourcesOf = (rel: string): SourceHit[] => {
    let s = sourceCache.get(rel);
    if (!s) {
      const lang = langForFile(rel);
      s = lang ? findSources(lang, content(rel)) : [];
      sourceCache.set(rel, s);
    }
    return s;
  };

  const findings: Finding[] = [];
  const emitted = new Set<string>();

  const emit = (sink: SinkHit, sinkFile: string, sinkSym: string | undefined, srcHit: SourceHit, srcFile: string, hops: PathStep[]): void => {
    const id = shortHash(`${srcFile}:${srcHit.line}->${sinkFile}:${sink.line}:${sink.kind}`);
    if (emitted.has(id)) return;
    emitted.add(id);

    const srcStep: PathStep = {
      file: srcFile,
      line: srcHit.line,
      symbol: enclosingSymbol(byRel.get(srcFile)!, srcHit.line),
      why: `untrusted input (${srcHit.kind}): ${truncate(srcHit.match)}`,
    };
    const path = [srcStep, ...hops];

    const sinkLine = lines(sinkFile)[sink.line - 1] ?? "";
    const lang = langForFile(sinkFile)!;
    const sanitizers = findSanitizers(lang, sinkLine, sink.kind);
    const crossFile = new Set(path.map((p) => p.file)).size > 1;

    const confidence = sanitizers.length ? "low" : "low"; // candidates are always low until verified
    const note = sanitizers.length
      ? ` Possible sanitizer on the sink line (${sanitizers.join("; ")}) — confirm it actually neutralizes this flow.`
      : "";

    findings.push({
      id,
      category: "taint",
      cwe: sink.cwe,
      title: `${sink.title}: untrusted input reaches ${sink.callee}()`,
      severity: sink.severity,
      confidence,
      source: { file: srcStep.file, line: srcStep.line, kind: srcHit.kind },
      sink: { file: sinkFile, line: sink.line, kind: sink.kind, symbol: sinkSym },
      path,
      message:
        `${crossFile ? "Cross-file" : "Intra-file"} candidate: ${srcHit.kind} input at ${srcStep.file}:${srcStep.line} ` +
        `may reach the ${sink.kind} sink ${sink.callee}() at ${sinkFile}:${sink.line} through ${path.length - 1} hop(s). ` +
        `${sink.note}${note} Heuristic — verify the data actually reaches the sink unsanitized before trusting it.`,
      tool: "ultrasec",
      references: [cweUrl(sink.cwe)],
      status: "open",
    });
  };

  for (const file of scan.files) {
    const lang = langForFile(file.rel);
    if (!lang) continue;

    for (const sink of findSinks(lang, file.calls)) {
      const sinkSym = enclosingSymbol(file, sink.line);
      const sinkStep: PathStep = {
        file: file.rel,
        line: sink.line,
        symbol: sinkSym,
        why: `${sink.kind} sink: ${sink.callee}()`,
      };

      type Frame = { file: string; sym?: string; entryLine: number; hops: PathStep[]; depth: number };
      const start: Frame = { file: file.rel, sym: sinkSym, entryLine: sink.line, hops: [sinkStep], depth: 0 };
      const queue: Frame[] = [start];
      const visited = new Set<string>([`${file.rel}#${sinkSym ?? sink.line}`]);

      while (queue.length) {
        const fr = queue.shift()!;

        // A source at/above the entry line in this frame's file closes a path.
        const above = sourcesOf(fr.file).filter((s) => s.line <= fr.entryLine);
        if (above.length) {
          const nearest = above.reduce((a, b) => (b.line > a.line ? b : a));
          emit(sink, file.rel, sinkSym, nearest, fr.file, fr.hops);
        }

        if (fr.depth >= MAX_DEPTH || !fr.sym) continue;

        // Walk back to callers of this frame's symbol, as long as it is exported
        // from this file. (We don't require it to be the *only* definition — a
        // name shared across files shouldn't silently drop a real taint path;
        // recall-oriented, the AI adjudicates.)
        // Array.isArray guards: symbol names can collide with Object.prototype
        // members ("toString", "constructor", …), so plain-object lookups by name
        // may return inherited functions instead of undefined.
        const defs = graph.symbolDefs[fr.sym];
        if (!Array.isArray(defs) || !defs.includes(fr.file)) continue;

        // Step back to callers via the precomputed reverse index — O(callers),
        // not O(files) per frame. The index is pre-sorted by (file, line), so the
        // BFS visits callers in exactly the order the old double loop did.
        const callerList = graph.callersBySymbol?.[fr.sym];
        for (const caller of Array.isArray(callerList) ? callerList : []) {
          if (caller.file === fr.file) continue;
          const key = `${caller.file}#${caller.symbol ?? caller.line}`;
          if (visited.has(key)) continue;
          visited.add(key);
          const hop: PathStep = { file: caller.file, line: caller.line, symbol: caller.symbol, why: `calls ${fr.sym}()` };
          queue.push({ file: caller.file, sym: caller.symbol, entryLine: caller.line, hops: [hop, ...fr.hops], depth: fr.depth + 1 });
        }
      }
    }
  }

  // Rank, THEN cap — so the kept candidates are the important ones (not whatever
  // happened to be enumerated first in alphabetical file order). Proximity = path
  // length: fewer source→sink hops is closer to the attack surface, hence riskier.
  const crossFile = (f: Finding): number => (f.path && new Set(f.path.map((p) => p.file)).size > 1 ? 1 : 0);
  const proximity = (f: Finding): number => (f.path ? f.path.length : Number.MAX_SAFE_INTEGER);
  findings.sort(
    (a, b) =>
      severityRank(a.severity) - severityRank(b.severity) ||
      proximity(a) - proximity(b) ||
      crossFile(b) - crossFile(a) ||
      byStr(a.id, b.id),
  );

  const total = findings.length;
  const kept = total > maxCandidates ? findings.slice(0, maxCandidates) : findings;
  return { findings: kept, truncated: total - kept.length, total };
}
