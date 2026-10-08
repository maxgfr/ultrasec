import { badField, coerceRows, describeValue, notInVocabulary, requireUsable, type DroppedRow, type ParseResult } from "../apply-parse.js";
import { ingestDiscoveries, type Discovery } from "../investigate.js";
import type { Dossier } from "../store.js";
import { CATEGORIES, normalizeCategory, SEVERITIES, type Finding, type Severity } from "../types.js";
import { findingCitations } from "./brief.js";
import { familyCategory, type Candidate, type CouncilTodo } from "./consolidate.js";
import type { Decision } from "./ledger.js";
import { redactReviewerText } from "./redact.js";

// `council --apply <decisions.json>` — the orchestrator's verdicts on the
// candidates, folded back.
//
// Verification never leaves the orchestrator: an external reviewer proposes,
// the agent that can open the code, run the library and read the trust model
// decides. An accepted candidate goes in through `ingestDiscoveries` — the same
// citation gate, the same `ultrasec-ai` tool, `status: open` — and is then
// adjudicated by `verify` like any other candidate. A rejected one is recorded
// in the ledger WITH its reason, so the report can say what the council raised
// and why it did not survive. Contestations of existing findings are a worklist
// and are never applied here: changing a verdict is `verify`'s job.

export const DECISIONS = ["accept", "reject"] as const;
export type DecisionKind = (typeof DECISIONS)[number];

export interface DecisionRow {
  id: string;
  decision: DecisionKind;
  reason: string;
  title?: string;
  category?: Discovery["category"];
  severity?: Severity;
  cwe?: string;
  message?: string;
  file?: string;
  line?: number;
}

export const DECISION_REQUIREMENT = `id (a council candidate id), decision among ${DECISIONS.join("|")}, and a non-empty reason on every reject`;

/**
 * Parse a decisions file: an array (or `{decisions: [...]}`) of
 * `{id, decision, reason, …overrides}`. Row-tolerant, container fail-closed —
 * the contract every `--apply` in this engine keeps. A `reject` without a
 * reason is refused: a rejection the report cannot explain is one nobody can
 * review.
 */
export function parseDecisions(raw: string): ParseResult<DecisionRow> {
  const arr = coerceRows(JSON.parse(raw) as unknown, ["decisions", "candidates"], "decisions");
  const rows: DecisionRow[] = [];
  const dropped: DroppedRow[] = [];
  for (const [index, r] of arr.entries()) {
    if (!r || typeof r !== "object" || Array.isArray(r)) {
      dropped.push({ index, reason: badField("row", r, "an object") });
      continue;
    }
    const d = r as Record<string, unknown>;
    const bad: string[] = [];
    if (typeof d.id !== "string" || !d.id) bad.push(badField("id", d.id, "a candidate id"));
    if (!(DECISIONS as readonly string[]).includes(d.decision as string)) bad.push(notInVocabulary("decision", d.decision, DECISIONS));
    const reason = typeof d.reason === "string" ? d.reason.trim() : "";
    if (d.decision === "reject" && !reason) bad.push(`reason ${describeValue(d.reason)} — a reject must say why`);
    if (d.severity !== undefined && !(SEVERITIES as readonly string[]).includes(d.severity as string))
      bad.push(notInVocabulary("severity", d.severity, SEVERITIES));
    const cat = d.category === undefined ? undefined : normalizeCategory(d.category);
    if (d.category !== undefined && !cat) bad.push(notInVocabulary("category", d.category, CATEGORIES));
    if (d.line !== undefined && (!Number.isInteger(d.line) || (d.line as number) < 0)) bad.push(badField("line", d.line, "an integer ≥ 0"));
    if (d.file !== undefined && typeof d.file !== "string") bad.push(badField("file", d.file, "a string"));
    if (bad.length) {
      dropped.push({ index, reason: `${typeof d.id === "string" ? `${d.id}: ` : ""}${bad.join(", ")}` });
      continue;
    }
    rows.push({
      id: d.id as string,
      decision: d.decision as DecisionKind,
      reason,
      ...(typeof d.title === "string" && d.title ? { title: d.title } : {}),
      ...(cat ? { category: cat.category } : {}),
      ...(typeof d.severity === "string" ? { severity: d.severity as Severity } : {}),
      ...(typeof d.cwe === "string" && d.cwe ? { cwe: d.cwe } : {}),
      ...(typeof d.message === "string" && d.message ? { message: d.message } : {}),
      ...(typeof d.file === "string" && d.file ? { file: d.file } : {}),
      ...(typeof d.line === "number" ? { line: d.line } : {}),
    });
  }
  return requireUsable({ rows, dropped }, arr.length, DECISION_REQUIREMENT);
}

export interface CouncilApplyResult {
  findings: Finding[];
  accepted: Decision[];
  rejected: Decision[];
  /** Rows naming no candidate, or an accepted one that cannot become a discovery. */
  refused: { id: string; reason: string }[];
  ingested: number;
  folded: number;
}

/** The discovery an accepted candidate becomes, or why it cannot become one. */
function toDiscovery(c: Candidate, row: DecisionRow): Discovery | string {
  const severity = row.severity ?? c.severity;
  if (!severity) return "the candidate states no severity and the decision gives none";
  const file = row.file ?? c.primary?.file;
  const line = row.line ?? c.primary?.line;
  if (!file || line === undefined) return "no resolvable citation on the candidate and none in the decision";
  const credit = `Second opinion (council): raised by ${c.sources.join(", ")} — corroboration ${c.corroboration} is a prior, not a verdict.`;
  const message = redactReviewerText(row.message ?? [c.scenario, credit, row.reason ? `Orchestrator: ${row.reason}` : ""].filter(Boolean).join("\n\n"));
  const cwe = row.cwe ?? c.cwe;
  return {
    title: redactReviewerText(row.title ?? c.title),
    category: row.category ?? familyCategory(c.family),
    severity,
    ...(cwe ? { cwe } : {}),
    message,
    file,
    line,
  };
}

/** Locate the finding a discovery became (new) or folded into (existing). */
function landedOn(findings: readonly Finding[], d: Discovery): string | undefined {
  const at = `${d.file}:${d.line}`;
  return (
    findings.find((f) => f.title === d.title && findingCitations(f).includes(at)) ??
    findings.find((f) => findingCitations(f).includes(at) && (f.sources ?? [f.tool]).includes("ultrasec-ai"))
  )?.id;
}

export function applyCouncil(
  dossier: Dossier,
  todo: CouncilTodo,
  rows: readonly DecisionRow[],
  repo: string,
  opts: { context?: string } = {},
): CouncilApplyResult {
  const byId = new Map(todo.candidates.map((c) => [c.id, c]));
  const corroborated = new Set(todo.corroborations.map((c) => c.findingId));
  const accepted: Decision[] = [];
  const rejected: Decision[] = [];
  const refused: CouncilApplyResult["refused"] = [];
  const pending: { c: Candidate; d: Discovery }[] = [];

  for (const row of rows) {
    const c = byId.get(row.id);
    if (!c) {
      refused.push({
        id: row.id,
        reason: corroborated.has(row.id)
          ? "names a finding the run already holds (a corroboration) — nothing to ingest"
          : "no such candidate in COUNCIL.todo.json (re-run --parse?)",
      });
      continue;
    }
    if (row.decision === "reject") {
      rejected.push({ candidate: c.id, title: c.title, sources: c.sources, reason: redactReviewerText(row.reason), by: "orchestrator" });
      continue;
    }
    const d = toDiscovery(c, row);
    if (typeof d === "string") refused.push({ id: c.id, reason: d });
    else pending.push({ c, d });
  }

  const res = ingestDiscoveries(
    dossier,
    pending.map((p) => p.d),
    repo,
    opts,
  );
  const gate = new Map(res.rejected.map((r) => [r.discovery, r.reason]));
  for (const { c, d } of pending) {
    const why = gate.get(d);
    if (why) rejected.push({ candidate: c.id, title: c.title, sources: c.sources, reason: why, by: "citation-gate" });
    else {
      const findingId = landedOn(res.findings, d);
      accepted.push({ candidate: c.id, title: d.title, sources: c.sources, ...(findingId ? { findingId } : {}) });
    }
  }
  return { findings: res.findings, accepted, rejected, refused, ingested: res.ingested, folded: res.folded };
}

/** Merge new decisions into the ledger's, last decision per candidate winning. */
export function mergeDecisions(
  prev: { accepted: Decision[]; rejected: Decision[] },
  next: { accepted: Decision[]; rejected: Decision[] },
): { accepted: Decision[]; rejected: Decision[] } {
  const decided = new Set([...next.accepted, ...next.rejected].map((d) => d.candidate));
  const keep = (ds: Decision[]) => ds.filter((d) => !decided.has(d.candidate));
  return { accepted: [...keep(prev.accepted), ...next.accepted], rejected: [...keep(prev.rejected), ...next.rejected] };
}
