import { join } from "node:path";
import { readText } from "./walk.js";
import type { RepoScan, FileScan } from "./scan.js";
import type { Graph } from "./graph.js";
import { langForFile } from "./lang.js";
import { findSinks, findSources, findSanitizers, cweUrl, type SinkHit, type SourceHit } from "./catalog.js";
import { shortHash, byStr } from "./util.js";
import { SEVERITIES, type Finding, type PathStep, type Severity } from "./types.js";

const MAX_DEPTH = 6; // call-graph hops walked back from a sink
const MAX_FINDINGS = 1000;

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
export function enumerateTaint(scan: RepoScan, graph: Graph): Finding[] {
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
    if (findings.length >= MAX_FINDINGS) break;
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

        // Walk back to callers of this frame's symbol (only if uniquely defined here).
        const defs = graph.symbolDefs[fr.sym];
        if (!defs || defs.length !== 1 || defs[0] !== fr.file) continue;

        for (const caller of scan.files) {
          if (caller.rel === fr.file) continue;
          for (const c of caller.calls) {
            if (c.callee !== fr.sym) continue;
            const callerSym = enclosingSymbol(caller, c.line);
            const key = `${caller.rel}#${callerSym ?? c.line}`;
            if (visited.has(key)) continue;
            visited.add(key);
            const hop: PathStep = { file: caller.rel, line: c.line, symbol: callerSym, why: `calls ${fr.sym}()` };
            queue.push({ file: caller.rel, sym: callerSym, entryLine: c.line, hops: [hop, ...fr.hops], depth: fr.depth + 1 });
          }
        }
      }
    }
  }

  return findings.sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || byStr(a.id, b.id));
}
