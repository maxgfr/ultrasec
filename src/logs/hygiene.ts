// CWE-532 static logging-hygiene pass: a LINE-CONTENT check (not a taint flow) —
// flags a LOG_SINKS call site whose source line names a sensitive identifier
// (password/token/api-key/…) or contains a literal secret. Reuses `findSinks`'s
// call-matching (scoped to `LOG_SINKS` only — never the default sink catalog, so
// this never runs unless a caller explicitly invokes it) and `src/logs/secrets.ts`'s
// SECRET_PATTERNS + redact() (Task 6's patterns, unmodified — no duplicate
// parsers). Strictly opt-in (`scan --log-hygiene`) — never called from the
// default pipeline.

import { join } from "node:path";
import { readText } from "../walk.js";
import type { RepoScan, FileScan } from "../scan.js";
import { langForFile } from "../lang.js";
import { findSinks, LOG_SINKS, cweUrl } from "../catalog.js";
import { shortHash, byStr } from "../util.js";
import { SEVERITIES, type Finding, type Severity } from "../types.js";
import { redact, truncateEvidence } from "./secrets.js";

// Logging hygiene floods easily (every log line is a candidate line), so the
// cap is far tighter than the taint/orphan-sink passes' (default 1000).
const DEFAULT_MAX_CANDIDATES = 40;

// Sensitive-identifier NAME heuristic — catches `logger.info("pw=" + password)`
// even when the logged value isn't a recognizable secret LITERAL (that half is
// SECRET_PATTERNS, reused unmodified below).
const SENSITIVE_NAME_RE = /\b(pass(word|wd)?|secret|token|api[_-]?key|authorization|credential|private[_-]?key|ssn|card[_-]?number)\b/i;

export interface SensitiveLogOptions {
  /** Keep at most this many ranked candidates (default 40). Excess is reported, not dropped silently. */
  maxCandidates?: number;
}

export interface SensitiveLogResult {
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
  for (const s of file.symbols) if (s.line <= line && (!best || s.line > best.line)) best = s;
  return best?.name;
}

/**
 * CWE-532 candidates: every `LOG_SINKS` call site whose line names a sensitive
 * identifier OR contains a literal secret pattern. Message is the REDACTED line
 * (never the raw secret literal — `redact()` strips it before the string is
 * ever assembled into a Finding). Rank-then-cap 40 per run, truncation reported
 * — never silently dropped.
 */
export function enumerateSensitiveLogCandidates(scan: RepoScan, opts: SensitiveLogOptions = {}): SensitiveLogResult {
  const maxCandidates = opts.maxCandidates ?? DEFAULT_MAX_CANDIDATES;

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

    for (const sink of findSinks(lang, file.calls, LOG_SINKS)) {
      if (sink.kind !== "log") continue; // a default-catalog match on this call, not a log sink

      const raw = lines(file.rel)[sink.line - 1] ?? "";
      const nameHit = SENSITIVE_NAME_RE.test(raw);
      const { redacted, hits: secretHits } = redact(raw);
      if (!nameHit && secretHits.length === 0) continue; // benign log line — no finding

      const reasons: string[] = [];
      if (nameHit) reasons.push("sensitive identifier name on the log line");
      if (secretHits.length) reasons.push(`literal secret pattern(s): ${[...new Set(secretHits.map((h) => h.kind))].sort(byStr).join(", ")}`);

      findings.push({
        id: shortHash(`log-hygiene:${file.rel}:${sink.line}`),
        category: "logs",
        cwe: "CWE-532",
        title: `Sensitive data logged via ${sink.callee}()`,
        severity: "medium",
        confidence: "low",
        sink: { file: file.rel, line: sink.line, kind: "log", symbol: enclosingSymbol(file, sink.line) },
        message:
          `Possible sensitive-data log write at ${file.rel}:${sink.line} (${reasons.join("; ")}): \`${truncateEvidence(redacted.trim())}\`. ` +
          `Verify this isn't a live credential/PII before it ships to a log sink — redact or drop the field. ` +
          `A CRLF-stripping logger or redaction middleware already in place downgrades this to a hardening note.`,
        tool: "ultrasec",
        references: [cweUrl("CWE-532")],
        status: "open",
      });
    }
  }

  // Rank (most severe first), THEN cap — ties break on the stable content-hash id.
  findings.sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || byStr(a.id, b.id));

  const total = findings.length;
  const kept = total > maxCandidates ? findings.slice(0, maxCandidates) : findings;
  return { findings: kept, truncated: total - kept.length, total };
}
