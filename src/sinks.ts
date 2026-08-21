import { join } from "node:path";
import { readText } from "./walk.js";
import type { RepoScan } from "./scan.js";
import { enclosingSymbolName, localDefNames } from "./scan.js";
import { langForFile } from "./lang.js";
import { findSinks, findSanitizers, cweUrl, UNRESOLVED_RECEIVER } from "./catalog.js";
import { shortHash, byStr } from "./util.js";
import { SEVERITIES, type Finding, type Severity } from "./types.js";

const DEFAULT_MAX_CANDIDATES = 1000;

export interface SinkCandidateOptions {
  /** Keep at most this many ranked candidates (default 1000). Excess is reported, not dropped silently. */
  maxCandidates?: number;
}

export interface SinkCandidateResult {
  findings: Finding[];
  /** Candidates dropped by `maxCandidates` (0 = none). */
  truncated: number;
  /** Total candidates enumerated before the cap. */
  total: number;
}

function severityRank(s: Severity): number {
  return SEVERITIES.indexOf(s); // 0 = critical … 4 = info
}

/**
 * The severity ceiling for a sink nothing connects to a source.
 *
 * An orphan sink is a real dangerous callee with an unproven path to it. The
 * catalog severity answers "how bad if an attacker reaches this", and shipping
 * that number unchanged answered a question nobody asked: on the first large
 * audit, 182 orphan sinks were emitted — 11 of them `critical` — and **not one
 * survived adjudication**. Meanwhile the confirmed findings sat below them.
 *
 * `high` rather than `medium`: an orphan `exec()` in a request handler is still
 * the first thing to read on the page, and demoting the whole class to medium
 * would trade one miscalibration for its mirror image. The point is that it
 * cannot outrank a CONFIRMED critical, and with `reachability: "unproven"`
 * damping the risk score it no longer does.
 *
 * The floor never promotes: a `low` sink stays `low`.
 */
const ORPHAN_SEVERITY_CEILING: Severity = "high";

/** The lower of the two severities — a ceiling never promotes a finding. */
function cappedAt(current: Severity, ceiling: Severity): Severity {
  return severityRank(current) >= severityRank(ceiling) ? current : ceiling;
}

/**
 * Orphan-sink recall layer. `enumerateTaint` only emits a finding when a
 * dangerous sink can be connected BACK to an untrusted source through the
 * call-graph (`findSinks` is source-gated). A sink the summary graph can't
 * connect to a source — a single-file script with no call edges, a framework
 * dispatch the heuristic graph misses, a sink fed by config — therefore produces
 * ZERO findings today, even though the dangerous operation is sitting right
 * there. This pass closes that recall hole: every `findSinks` hit NOT already
 * represented by a (source-grounded) taint finding is emitted as a low-confidence
 * `sast` candidate — sink location only, no proven source→sink path — for the AI
 * to adjudicate, exactly like a taint candidate but without a proven source.
 *
 * It widens recall using ultrasec's OWN sink catalog (no new matchers, no
 * external tool), and like the taint pass it ranks-then-caps and REPORTS any
 * truncation — never silently drops. Opt-in (`scan --sinks`) so default
 * behaviour is unchanged.
 */
export function enumerateSinkCandidates(scan: RepoScan, covered: Finding[], opts: SinkCandidateOptions = {}): SinkCandidateResult {
  const maxCandidates = opts.maxCandidates ?? DEFAULT_MAX_CANDIDATES;

  // Sinks already represented by a (source-grounded) taint finding — those carry
  // a full path and are strictly more informative, so don't double-report them.
  const taken = new Set<string>();
  for (const f of covered) if (f.sink) taken.add(`${f.sink.file}:${f.sink.line}:${f.sink.kind ?? ""}`);

  const lineCache = new Map<string, string[]>();
  const lines = (rel: string): string[] => {
    let l = lineCache.get(rel);
    if (!l) lineCache.set(rel, (l = readText(join(scan.repo, rel)).split(/\r?\n/)));
    return l;
  };

  const findings: Finding[] = [];
  for (const file of scan.files) {
    const lang = langForFile(file.rel);
    if (!lang) continue;
    for (const sink of findSinks(lang, file.calls, undefined, file.imports, localDefNames(file.symbols))) {
      const key = `${file.rel}:${sink.line}:${sink.kind}`;
      if (taken.has(key)) continue; // covered by taint, or already emitted this pass
      taken.add(key);

      const sinkLine = lines(file.rel)[sink.line - 1] ?? "";
      const sanitizers = findSanitizers(lang, sinkLine, sink.kind);
      const note = sanitizers.length
        ? ` A possible sanitizer is present on the line (${sanitizers.join("; ")}) — confirm it neutralizes any untrusted input.`
        : "";
      // Same caveat the taint pass carries: an `ambiguous` rule matched by name
      // alone, with nothing to corroborate that this callee is what the rule
      // means. Worth a glance, not a headline.
      const receiverNote =
        sink.downgraded === UNRESOLVED_RECEIVER
          ? ` [${UNRESOLVED_RECEIVER}] Matched by NAME only — no receiver resolved and no corroborating import was visible, so \`${sink.callee}\` may not be a ${sink.kind} call at all.`
          : "";

      findings.push({
        id: shortHash(`sink:${file.rel}:${sink.line}:${sink.kind}`),
        category: "sast",
        cwe: sink.cwe,
        title: `${sink.title}: ${sink.callee}() sink (no source path found)`,
        severity: cappedAt(sink.severity, ORPHAN_SEVERITY_CEILING),
        confidence: "low",
        // Says out loud what `confidence: low` only implied, and what the
        // ranking now acts on: nothing in this run puts an attacker on this
        // line. An auditor who finds the path the summary graph missed confirms
        // it and the severity comes back with the evidence.
        reachability: "unproven",
        sink: { file: file.rel, line: sink.line, kind: sink.kind, symbol: enclosingSymbolName(file.symbols, sink.line) },
        message:
          `Dangerous ${sink.kind} sink ${sink.callee}() at ${file.rel}:${sink.line} that the cross-file taint pass ` +
          `could NOT connect to an untrusted source (orphan sink). Still worth a look — the source may arrive via a ` +
          `path the summary call-graph misses (framework dispatch, dynamic call, config). ` +
          `${sink.note}${note}${receiverNote} Confirm whether attacker-controlled data can reach it before trusting it.`,
        tool: "ultrasec",
        references: [cweUrl(sink.cwe)],
        status: "open",
      });
    }
  }

  // Rank (most severe first), THEN cap — so the kept candidates are the important
  // ones, not whatever was enumerated first in file order. Ties break on the
  // stable content-hash id.
  findings.sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || byStr(a.id, b.id));

  const total = findings.length;
  const kept = total > maxCandidates ? findings.slice(0, maxCandidates) : findings;
  return { findings: kept, truncated: total - kept.length, total };
}
