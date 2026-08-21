import { join } from "node:path";
import { readText } from "./walk.js";
import type { RepoScan } from "./scan.js";
import { enclosingSymbolName, localDefNames } from "./scan.js";
import type { Graph } from "./graph.js";
import { langForFile } from "./lang.js";
import { findSinks, findSources, findTextSinks, cweUrl, LOG_SINKS, UNRESOLVED_RECEIVER, type SinkHit, type SourceHit } from "./catalog.js";
import { buildUnitMap, classifySourceScope, sanitizersAlongPath, scopeRank, traceDefUse, type UnitMap } from "./dataflow.js";
import { shortHash, byStr } from "./util.js";
import { SEVERITIES, type Finding, type PathStep, type Severity, type SourceScope } from "./types.js";

const DEFAULT_MAX_DEPTH = 6; // call-graph hops walked back from a sink
const DEFAULT_MAX_CANDIDATES = 1000;

export interface TaintOptions {
  /** Call-graph hops walked back from each sink (default 6). */
  maxDepth?: number;
  /** Keep at most this many ranked candidates (default 1000). Excess is reported, not dropped silently. */
  maxCandidates?: number;
  /** Union `LOG_SINKS` into the sink catalog for this run (opt-in `scan
   *  --log-hygiene`, CWE-117 log injection). Default false ⇒ the sink-matching
   *  step is byte-identical to before this option existed. */
  includeLogSinks?: boolean;
  /**
   * Drop candidates whose SOURCE is an environment read (`process.env`,
   * `os.getenv`). Opt-in, default false ⇒ enumeration unchanged.
   *
   * Treating the environment as attacker-controlled models configuration
   * injection, which is a real class — but it presumes the operator of the
   * deployment is a threat actor, and most trust models say otherwise. On one
   * real audit these accounted for 100 of the 138 refuted candidates, crowding
   * out the flows rooted in actual user input. The default stays permissive
   * (recall first); this is the knob for an auditor who has decided their
   * operator is trusted.
   */
  excludeEnvSources?: boolean;
  /**
   * Drop candidates whose source sits in a DIFFERENT function of the same file
   * (`sourceScope: "file"`). Opt-in, default false ⇒ enumeration unchanged.
   *
   * Those pairs share a file and nothing else: a `req.query` in one handler and
   * an `exec()` in another are connected only by co-location, and on a router
   * with twenty handlers the count grows quadratically. They are still emitted by
   * default — a value can travel between two functions through module state, and
   * recall comes first — but an auditor working a large web app can trade that
   * tail for a shorter queue.
   */
  strictScope?: boolean;
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

function truncate(s: string, n = 60): string {
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

/** Assignment sinks (`el.innerHTML = …`) are not calls, so they must not be
 *  rendered with call parentheses. */
function calleeLabel(sink: SinkHit): string {
  return sink.kind === "domxss" ? sink.callee : `${sink.callee}()`;
}

/** Said plainly in the source step, because "same file" and "same function" are
 *  very different claims and the dossier reader must not have to guess which. */
const SCOPE_WHY: Record<SourceScope, string> = {
  symbol: "",
  module: " — at file scope",
  file: " — in a DIFFERENT function of this file; co-location only, verify the value actually travels",
};

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
  const extraSinks = opts.includeLogSinks ? LOG_SINKS : undefined;
  const byRel = new Map(scan.files.map((f) => [f.rel, f]));
  const contentCache = new Map<string, string>();
  const sourceCache = new Map<string, SourceHit[]>();
  const lineCache = new Map<string, string[]>();
  const unitCache = new Map<string, UnitMap>();

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
  const unitsOf = (rel: string): UnitMap => {
    let u = unitCache.get(rel);
    if (!u) {
      const lang = langForFile(rel);
      unitCache.set(rel, (u = buildUnitMap(lines(rel), lang?.id ?? "")));
    }
    return u;
  };

  // file → files it links to (imports / resolved calls), for the ambiguity gate.
  const linkedTo = new Map<string, Set<string>>();
  for (const e of graph.edges) {
    let set = linkedTo.get(e.from);
    if (!set) linkedTo.set(e.from, (set = new Set()));
    set.add(e.to);
  }

  /**
   * Does `from` actually reference `to`? An import or a resolved call edge. A
   * caller with NO imports recorded stays permissive — absent data means "could
   * not see", not "none", the same rule `requireModule` follows.
   *
   * A looser variant that also accepted the target's class name appearing in the
   * caller's text (for Java's fully-qualified style) was tried and reverted: it
   * recovered nothing on OWASP Benchmark and added 47 candidates to this repo's
   * own scan, because short basenames like `util` or `types` appear everywhere.
   */
  const linksTo = (from: string, to: string): boolean => linkedTo.get(from)?.has(to) === true || (byRel.get(from)?.imports.length ?? 0) === 0;

  const findings: Finding[] = [];
  const emitted = new Set<string>();

  const emit = (
    sink: SinkHit,
    sinkFile: string,
    sinkSym: string | undefined,
    srcHit: SourceHit,
    srcFile: string,
    hops: PathStep[],
    frameEntryLine: number,
  ): void => {
    // Opt-in: treat deployment configuration as trusted (see excludeEnvSources).
    if (opts.excludeEnvSources && srcHit.kind === "env") return;

    const srcSymbols = byRel.get(srcFile)!.symbols;
    const sourceScope = classifySourceScope(srcSymbols, srcHit.line, frameEntryLine, unitsOf(srcFile));
    // Opt-in: co-location in a file is not a data path (see strictScope).
    if (opts.strictScope && sourceScope === "file") return;

    const id = shortHash(`${srcFile}:${srcHit.line}->${sinkFile}:${sink.line}:${sink.kind}`);
    if (emitted.has(id)) return;
    emitted.add(id);

    const srcStep: PathStep = {
      file: srcFile,
      line: srcHit.line,
      symbol: enclosingSymbolName(srcSymbols, srcHit.line),
      why: `untrusted input (${srcHit.kind}): ${truncate(srcHit.match)}${SCOPE_WHY[sourceScope]}`,
    };
    const path = [srcStep, ...hops];

    // Does the bound value still reach the line that closed this frame? For the
    // seed frame that line IS the sink; for a caller frame it is the call that
    // leads to it — the same question one hop out.
    const dataflow = traceDefUse(lines(srcFile), srcHit.line, srcHit.match, frameEntryLine);

    // Every hop, not just the sink line: defensive code is normally written on
    // the line before the dangerous call, or at an intermediate hop entirely.
    const sanitizers = sanitizersAlongPath(path, sink.kind, (f, l) => lines(f)[l - 1] ?? "");
    const crossFile = new Set(path.map((p) => p.file)).size > 1;

    const note = sanitizers.length
      ? ` Possible sanitizer along the path — ${sanitizers.map((s) => `${s.file}:${s.line} (${s.note})`).join("; ")} — confirm it actually neutralizes this flow.`
      : "";
    const flowNote =
      dataflow === "unlinked"
        ? " The value bound at the source is not mentioned again at the sink — it may travel through state this walk cannot see, or not at all."
        : "";
    // An `ambiguous` catalog rule that nothing corroborated. Say so in the
    // message rather than only in the severity, so the adjudicator knows which
    // question to answer first: is this callee even the thing the rule names?
    const receiverNote =
      sink.downgraded === UNRESOLVED_RECEIVER
        ? ` [${UNRESOLVED_RECEIVER}] The callee \`${sink.callee}\` was matched by NAME only — no receiver resolved and no corroborating import was visible, so this may not be a ${sink.kind} call at all. Rated below the catalog severity until you confirm what it resolves to.`
        : "";

    findings.push({
      id,
      category: "taint",
      cwe: sink.cwe,
      title: `${sink.title}: untrusted input reaches ${calleeLabel(sink)}`,
      severity: sink.severity,
      confidence: "low", // candidates are always low until verified
      source: { file: srcStep.file, line: srcStep.line, kind: srcHit.kind },
      sink: { file: sinkFile, line: sink.line, kind: sink.kind, symbol: sinkSym },
      path,
      sourceScope,
      ...(dataflow ? { dataflow } : {}),
      message:
        `${crossFile ? "Cross-file" : "Intra-file"} candidate: ${srcHit.kind} input at ${srcStep.file}:${srcStep.line} ` +
        `may reach the ${sink.kind} sink ${calleeLabel(sink)} at ${sinkFile}:${sink.line} through ${path.length - 1} hop(s). ` +
        `${sink.note}${note}${flowNote}${receiverNote} Heuristic — verify the data actually reaches the sink unsanitized before trusting it.`,
      tool: "ultrasec",
      references: [cweUrl(sink.cwe)],
      status: "open",
    });
  };

  for (const file of scan.files) {
    const lang = langForFile(file.rel);
    if (!lang) continue;

    // Call sinks plus ASSIGNMENT sinks. `el.innerHTML = x` is the commonest DOM
    // XSS shape in the wild and is not a call at all, so a call-only catalog
    // could never see it.
    const sinkHits = [...findSinks(lang, file.calls, extraSinks, file.imports, localDefNames(file.symbols)), ...findTextSinks(lang, content(file.rel))];

    for (const sink of sinkHits) {
      const sinkSym = enclosingSymbolName(file.symbols, sink.line);
      const sinkStep: PathStep = {
        file: file.rel,
        line: sink.line,
        symbol: sinkSym,
        why: `${sink.kind} sink: ${calleeLabel(sink)}`,
      };

      type Frame = { file: string; sym?: string; entryLine: number; hops: PathStep[]; depth: number };
      const start: Frame = { file: file.rel, sym: sinkSym, entryLine: sink.line, hops: [sinkStep], depth: 0 };
      const queue: Frame[] = [start];
      const visited = new Set<string>([`${file.rel}#${sinkSym ?? sink.line}`]);

      while (queue.length) {
        const fr = queue.shift()!;

        // A source at/above the entry line in this frame's file closes a path.
        // The nearest one wins; `emit` records how it is scoped relative to the
        // frame, since "same file" and "same function" are very different claims.
        const above = sourcesOf(fr.file).filter((s) => s.line <= fr.entryLine);
        if (above.length) {
          const nearest = above.reduce((a, b) => (b.line > a.line ? b : a));
          emit(sink, file.rel, sinkSym, nearest, fr.file, fr.hops, fr.entryLine);
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
        //
        // AMBIGUOUS NAMES: the index is keyed by raw callee name, so a symbol
        // defined in many files (`handle`, `process`, `doSomething`) links every
        // caller of ANY of them to every one of them. Measured on OWASP Benchmark,
        // `doSomething` is defined in 881 files and produced cross-file paths
        // between wholly unrelated ones. When the name is ambiguous, require a
        // real link (an import or a resolved call edge) from the caller's file to
        // this one. The gate is skipped for a caller file with NO imports
        // recorded at all — absent data means "could not see", not "none", the
        // same rule `requireModule` follows. Keying on recorded imports rather
        // than on in-repo edges matters: a file importing only framework
        // packages has zero in-repo edges, and that is evidence the hop is a
        // guess, not evidence that we failed to look.
        const ambiguous = Array.isArray(defs) && defs.length > 1;
        const callerList = graph.callersBySymbol?.[fr.sym];
        for (const caller of Array.isArray(callerList) ? callerList : []) {
          if (caller.file === fr.file) continue;
          if (ambiguous && !linksTo(caller.file, fr.file)) continue;
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
  // happened to be enumerated first in alphabetical file order). Scope outranks
  // proximity: a two-hop chain whose source is in the same function beats a
  // one-hop pairing that shares only a file. Proximity = path length: fewer
  // source→sink hops is closer to the attack surface, hence riskier.
  const crossFile = (f: Finding): number => (f.path && new Set(f.path.map((p) => p.file)).size > 1 ? 1 : 0);
  const proximity = (f: Finding): number => (f.path ? f.path.length : Number.MAX_SAFE_INTEGER);
  const unlinked = (f: Finding): number => (f.dataflow === "unlinked" ? 1 : 0);
  findings.sort(
    (a, b) =>
      severityRank(a.severity) - severityRank(b.severity) ||
      scopeRank(a.sourceScope) - scopeRank(b.sourceScope) ||
      unlinked(a) - unlinked(b) ||
      proximity(a) - proximity(b) ||
      crossFile(b) - crossFile(a) ||
      byStr(a.id, b.id),
  );

  const total = findings.length;
  const kept = total > maxCandidates ? findings.slice(0, maxCandidates) : findings;
  return { findings: kept, truncated: total - kept.length, total };
}
