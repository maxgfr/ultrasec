import { SEVERITIES, type Finding, type Severity, type Status } from "./types.js";
import { byStr } from "./util.js";

// How findings are ordered, in one place.
//
// Three renderers had their own copy of `(b.risk ?? -1) - (a.risk ?? -1) ||
// severity || id` — DOSSIER.md, the Markdown report, and the HTML — and all
// three ranked the same way: by the engine's opinion of a candidate, ignoring
// what the audit had since DECIDED about it.
//
// On the first large audit that produced a report whose first fifteen entries
// were thirteen refuted candidates, while the three confirmed criticals sat at
// ranks 1343-1366 of 1366. Two independent causes compounded:
//
//   1. `risk` is attached during `scan`. Findings ingested later — every
//      `investigate`/`variants` discovery — had none, and `?? -1` sorts them
//      below everything. The most precise producer in the run was ranked last
//      for arriving late. (Fixed at the source: `ingestDiscoveries` now scores.)
//   2. Nothing in the sort knew about `status`. A candidate the auditor had
//      spent an argued refutation on still outranked one they had confirmed.
//
// The fix for (2) is this module. Adjudication is the most expensive signal in
// the whole pipeline — it is the one thing a human or an agent actually decided
// — so it sorts first, and `risk` orders WITHIN a decision rather than across
// decisions.

/**
 * Decision order. `confirmed` is what the audit is for; `needs-human` is the
 * next thing anyone must act on; `open` is undone work; `dismissed` is the
 * archive, and belongs under everything.
 */
const STATUS_RANK: Record<Status, number> = {
  confirmed: 0,
  "needs-human": 1,
  open: 2,
  dismissed: 3,
};

/** Unknown/absent status sorts with `open` — undone, not decided, not archived. */
export function statusRank(s: Status | undefined | null): number {
  return (s && STATUS_RANK[s]) ?? STATUS_RANK.open;
}

/**
 * What `riskScore` gives a finding from severity alone — `0.6 × weight × 100`,
 * the exact severity-only branch of the composite.
 */
const SEVERITY_ONLY_RISK: Record<Severity, number> = { critical: 60, high: 48, medium: 30, low: 15, info: 6 };

/**
 * A finding's rank score: its composite `risk`, or what severity alone implies.
 *
 * The fallback is the whole point. `risk` is attached during `scan`, so a finding
 * ingested afterwards has none, and the previous `risk ?? -1` read "unscored" as
 * "worthless" — sorting it below every scored candidate including the refuted
 * ones. `ingestDiscoveries` now scores what it ingests, but that only fixes runs
 * made from here on: a dossier already on disk still carries unscored findings,
 * and re-rendering it must not bury them.
 *
 * Ranking has no business depending on WHEN a finding was added. Scoring the
 * fallback the same way the engine scores a severity-only finding makes the
 * order a property of the finding instead.
 */
export function rankScore(f: Finding): number {
  return f.risk ?? SEVERITY_ONLY_RISK[f.severity] ?? 0;
}

/**
 * Severity rank, with an unknown value sorted LAST.
 *
 * `SEVERITIES.indexOf(undefined)` is -1, which put a malformed finding above
 * every critical in every ranked list — the same null-severity batch that made
 * `render` throw also silently headlined itself.
 */
export function severityRank(s: Severity | undefined | null): number {
  const at = SEVERITIES.indexOf(s as Severity);
  return at === -1 ? SEVERITIES.length : at;
}

/**
 * The audit's canonical order: what was decided, then how urgent, then how bad,
 * then a stable tiebreak.
 *
 * Deterministic — the id tiebreak means two runs over an unchanged dossier
 * produce byte-identical reports, which the whole artifact contract depends on.
 */
export function compareFindings(a: Finding, b: Finding): number {
  return statusRank(a.status) - statusRank(b.status) || rankScore(b) - rankScore(a) || severityRank(a.severity) - severityRank(b.severity) || byStr(a.id, b.id);
}

/** `compareFindings` as a sort, on a copy. */
export function sortFindings(fs: readonly Finding[]): Finding[] {
  return fs.slice().sort(compareFindings);
}

/**
 * Order WITHIN one decision tier — risk, then severity, then id.
 *
 * For the callers that have already split by status (the report's per-status
 * sections, the HTML's confirmed/dismissed split) and would otherwise pay for a
 * status comparison whose answer is constant.
 */
export function compareWithinStatus(a: Finding, b: Finding): number {
  return rankScore(b) - rankScore(a) || severityRank(a.severity) - severityRank(b.severity) || byStr(a.id, b.id);
}
