import type { Dossier } from "./store.js";
import { BROCARDS, VERDICTS, type Brocard, type Finding, type Status, type Verdict } from "./types.js";
import { byStr, withStageNote } from "./util.js";
import { proposedFor, type ProposedAdjudication } from "./noise.js";
import { parseIdVerdictRows, type ParseResult } from "./apply-parse.js";

// The adversarial verification gate. The engine emits a claim↔evidence worklist;
// the AI (skeptic subagents) adjudicates each finding by reading the dossier's
// real code, then `--apply` folds the verdicts back in. The policy is
// deliberately CONSERVATIVE: aggressive auto-suppression discards real bugs
// (research shows ~22%), so a high/critical finding is only dismissed on an
// explicit `refuted`; anything merely `unsupported`/uncertain becomes
// `needs-human` rather than disappearing.

export interface VerifyItem {
  id: string;
  severity: string;
  cwe?: string;
  title: string;
  category: string;
  /** What must hold for this to be a real, exploitable issue. */
  claim: string;
  /** Files the adjudicator should open. */
  files: string[];
  /** Filled by the adjudicator. */
  verdict: Verdict | null;
  note: string;
  /**
   * Filled by the adjudicator on a `refuted` verdict — the named ground.
   *
   * Present as an explicit `null` because its ABSENCE was the defect: the
   * vocabulary was described in the Markdown brief while the JSON an adjudicator
   * actually fills had no slot for it, so grounds were written into `note` and
   * `check --semantic` then reported every one of them as unargued. On the first
   * real audit that was 96 dismissals and zero brocards.
   */
  brocard: Brocard | null;
  exploitPath?: string;
  /** Machine-proposed ground for a noise-by-construction finding. A suggestion
   *  to accept or refuse — never a filled-in verdict. */
  proposed?: ProposedAdjudication;
  /** Upstream-agent signal (e.g. deepsec revalidation verdict) — a HINT shown to
   *  the adjudicator, never auto-applied. Absent unless `priorAnalysis` exists. */
  priorSignal?: string;
  /** Set only on a RE-OPENED item (`--all`): the verdict an earlier pass already
   *  recorded before escalating it to needs-human. Its presence is what tells the
   *  adjudicator this row is not new work. */
  priorVerdict?: Verdict;
}

export interface VerdictInput {
  id: string;
  verdict: Verdict;
  note?: string;
  exploitPath?: string;
  /** Named ground for a refutation (see BROCARDS). Ignored on other verdicts. */
  brocard?: Brocard;
}

/**
 * A `needs-human` finding that ALREADY carries a verdict was adjudicated by an
 * earlier pass — someone read it and escalated it deliberately. One that does
 * not was escalated by some other stage and has never been ruled on.
 *
 * That distinction is the whole of the delta: it is the only "already
 * adjudicated" marker the dossier holds (there is no timestamp and no verdict
 * history), and it is enough.
 */
function reOpened(f: Finding): boolean {
  return f.status === "needs-human" && f.verdict !== undefined;
}

/** Findings still needing adjudication (open or previously needs-human). */
function pending(findings: Finding[]): Finding[] {
  return findings.filter((f) => f.status === "open" || f.status === "needs-human");
}

export interface WorklistOptions {
  /**
   * Re-emit findings an earlier pass already adjudicated as `needs-human`.
   *
   * Off by default, and that default is a behaviour change with a body count.
   * The worklist used to re-emit every non-terminal finding unconditionally, so
   * a batch meant to cover 11 new discoveries arrived holding 171 rows; filling
   * it in flipped 160 already-argued advisories to `supported` in one apply.
   * Re-visiting an escalation is legitimate — it is why the re-emission exists —
   * but it has to be asked for.
   */
  all?: boolean;
}

/** How the worklist was composed, for the header and the CLI summary. */
export interface WorklistCounts {
  fresh: number;
  reOpened: number;
  /** Re-opened items withheld because `--all` was not passed. */
  withheld: number;
}

export function worklistCounts(dossier: Dossier, opts: WorklistOptions = {}): WorklistCounts {
  const p = pending(dossier.findings);
  const re = p.filter(reOpened).length;
  return { fresh: p.length - re, reOpened: opts.all ? re : 0, withheld: opts.all ? 0 : re };
}

export function buildWorklist(dossier: Dossier, opts: WorklistOptions = {}): VerifyItem[] {
  return pending(dossier.findings)
    .filter((f) => opts.all || !reOpened(f))
    .slice()
    .sort((a, b) => byStr(a.id, b.id))
    .map((f) => {
      const files = new Set<string>();
      for (const p of f.path ?? []) files.add(`${p.file}:${p.line}`);
      if (f.sink) files.add(`${f.sink.file}:${f.sink.line}`);
      if (f.source) files.add(`${f.source.file}:${f.source.line}`);
      const item: VerifyItem = {
        id: f.id,
        severity: f.severity,
        cwe: f.cwe,
        title: f.title,
        category: f.category,
        claim: f.message,
        files: [...files],
        verdict: null,
        note: "",
        brocard: null,
      };
      const proposed = proposedFor(f);
      if (proposed) item.proposed = proposed;
      const pa = f.priorAnalysis;
      if (pa?.revalidationVerdict) item.priorSignal = `${pa.tool} revalidation: ${pa.revalidationVerdict}`;
      if (reOpened(f)) item.priorVerdict = f.verdict;
      return item;
    });
}

/** Round-robin slice `i` of `n` over the stable worklist order (balanced shards). */
export function shard<T>(items: T[], n: number, i: number): T[] {
  return items.filter((_, idx) => idx % n === i);
}

export function renderWorklistMd(items: VerifyItem[], context?: string, counts?: WorklistCounts): string {
  const L: string[] = [];
  L.push(`# ultrasec verification worklist (${items.length})`);
  L.push("");
  // Say what this batch IS. A worklist that silently mixes new candidates with
  // findings someone already argued over reads as pure delta, and gets filled in
  // as one — which is how 160 adjudicated advisories were re-verdicted at once.
  if (counts && (counts.reOpened || counts.withheld)) {
    if (counts.withheld)
      L.push(`**${counts.fresh} new** · ${counts.withheld} already adjudicated as needs-human and NOT shown — pass \`--all\` to re-open them.`);
    else L.push(`**${counts.fresh} new** · ${counts.reOpened} re-opened (already adjudicated once; each carries its \`priorVerdict\`).`);
    L.push("");
  }
  L.push(`For each item: open the cited code (\`ultrasec dossier <id>\`), decide whether`);
  L.push(`the flow is **real and exploitable**, and set a verdict:`);
  L.push(`\`supported\` · \`partial\` · \`unsupported\` · \`refuted\` (+ a short note, and an`);
  L.push(`\`exploitPath\` when supported). Save as verdicts.json (array of`);
  L.push(`{id, verdict, note, exploitPath, brocard}) and run \`ultrasec verify --apply verdicts.json\`.`);
  L.push("");
  L.push(`> Be skeptical, but do NOT dismiss a high/critical finding unless you can`);
  L.push(`> positively **refute** it. Uncertain ⇒ leave it for a human.`);
  L.push("");
  L.push(`On \`refuted\`, name the ground in the item's \`brocard\` field — one of:`);
  L.push(BROCARDS.map((b) => `\`${b}\``).join(" · "));
  L.push("");
  L.push(`A prose \`note\` is not a ground: \`check --semantic\` reads \`brocard\`, and a`);
  L.push(`carefully-argued note in the wrong field still reports as an unargued dismissal.`);
  L.push(`Not proving something is not disproving it: a refutation you cannot name a ground for`);
  L.push(`is \`unsupported\`. See references/dismissal-brocards.md.`);
  L.push("");
  // Project context (presence-gated): the agent-authored CONTEXT.md frames every
  // judgment below. Absent CONTEXT.md ⇒ omitted (output byte-identical to today).
  if (context) {
    L.push(`## Project context`);
    L.push(`_From \`CONTEXT.md\` — the project's trust model; background, never a verdict._`);
    L.push("");
    L.push(context);
    L.push("");
  }
  for (const it of items) {
    L.push(`## ${it.id} — [${it.severity}] ${it.title}`);
    if (it.cwe) L.push(`- ${it.cwe} · ${it.category}`);
    L.push(`- files: ${it.files.map((f) => `\`${f}\``).join(", ")}`);
    L.push(`- claim: ${it.claim}`);
    if (it.priorSignal) L.push(`- signal (not a verdict — adjudicate yourself): ${it.priorSignal}`);
    if (it.proposed)
      L.push(`- proposed ground \`${it.proposed.ground}\` (${it.proposed.class}) — ${it.proposed.why}. Accept it or refuse it; it is not a verdict.`);
    if (it.priorVerdict) L.push(`- **re-opened** — an earlier pass ruled \`${it.priorVerdict}\` and escalated it. Not new work.`);
    L.push("");
  }
  return L.join("\n") + "\n";
}

export interface ApplyResult {
  findings: Finding[];
  applied: number;
  confirmed: number;
  dismissed: number;
  needsHuman: number;
  /** Conservative overrides: unsupported/partial high-severity kept for a human. */
  keptForHuman: { id: string; verdict: Verdict; severity: string }[];
  /** Stale verdicts: ids that resolve to no finding (sorted) — reported, never silently dropped. */
  ignored: string[];
  /**
   * Verdicts that CHANGED a finding an earlier pass had already ruled on.
   *
   * Re-applying the same verdict is a no-op and stays quiet; this is only the
   * rows that moved someone's existing judgement. Surfaced so a batch can never
   * re-decide 160 findings without saying so, and gated behind `--re-verdict`
   * under `--strict`.
   */
  reVerdicted: { id: string; from: Verdict | undefined; to: Verdict; wasStatus: Status }[];
}

/** Critical/high — the tier the conservative policy refuses to auto-dismiss on
 *  anything short of an explicit refutation. Exported so every adjudicating stage
 *  (triage, revalidate, powered cross-check) shares the EXACT same boundary. */
export function isHigh(sev: string): boolean {
  return sev === "critical" || sev === "high";
}

/** Map a verdict onto a finding status under the conservative policy. Exported so
 *  every stage that adjudicates findings reuses the single source of truth. */
export function nextStatus(verdict: Verdict, severity: string): Status {
  switch (verdict) {
    case "supported":
      return "confirmed";
    case "refuted":
      return "dismissed"; // an explicit contradiction — safe to drop
    case "unsupported":
      return isHigh(severity) ? "needs-human" : "dismissed";
    case "partial":
      return "needs-human";
    default:
      return "needs-human"; // unknown verdict: never silently drop
  }
}

export function applyVerdicts(dossier: Dossier, verdicts: VerdictInput[]): ApplyResult {
  const byId = new Map<string, VerdictInput>();
  for (const v of verdicts) byId.set(v.id, v); // last-wins on dupes
  const known = new Set(dossier.findings.map((f) => f.id));
  const ignored = [...byId.keys()].filter((id) => !known.has(id)).sort(byStr);

  let confirmed = 0,
    dismissed = 0,
    needsHuman = 0,
    applied = 0;
  const keptForHuman: ApplyResult["keptForHuman"] = [];
  const reVerdicted: ApplyResult["reVerdicted"] = [];

  const findings = dossier.findings.map((f) => {
    const v = byId.get(f.id);
    if (!v) return f;
    applied++;
    // Already ruled on, and this row rules differently. `status !== "open"` is
    // the marker; an unchanged verdict is left quiet so a re-apply of the same
    // file reports nothing.
    if (f.status !== "open" && f.verdict !== v.verdict) reVerdicted.push({ id: f.id, from: f.verdict, to: v.verdict, wasStatus: f.status });
    const status = nextStatus(v.verdict, f.severity);
    if (v.verdict === "unsupported" && isHigh(f.severity)) keptForHuman.push({ id: f.id, verdict: v.verdict, severity: f.severity });
    if (status === "confirmed") confirmed++;
    else if (status === "dismissed") dismissed++;
    else needsHuman++;
    const next: Finding = {
      ...f,
      status,
      verdict: v.verdict,
      confidence: v.verdict === "supported" ? "high" : v.verdict === "partial" ? "medium" : f.confidence,
    };
    if (v.exploitPath) next.exploitPath = v.exploitPath;
    // Only meaningful on a refutation: it names the ground the dismissal stands on.
    if (v.brocard && v.verdict === "refuted") next.brocard = v.brocard;
    if (v.note) next.message = withStageNote(f.message, "Verdict", v.verdict, v.note);
    return next;
  });

  reVerdicted.sort((a, b) => byStr(a.id, b.id));
  return { findings, applied, confirmed, dismissed, needsHuman, keptForHuman, ignored, reVerdicted };
}

/**
 * Parse a verdicts file body: a JSON array or {verdicts:[...]} (the shape the
 * orchestrate-emitted contracts return). FAIL-CLOSED: an unrecognized container
 * shape, or rows that all get dropped, throws instead of yielding 0 rows — a
 * fold that silently applies nothing is exactly the bug the gate exists to stop.
 */
export function parseVerdicts(raw: string): ParseResult<VerdictInput> {
  return parseIdVerdictRows(raw, {
    wrapperKeys: ["verdicts"],
    label: "verdicts",
    verdicts: VERDICTS,
    build: (v, verdict) => ({
      id: v.id as string,
      verdict: verdict as Verdict,
      note: v.note as string | undefined,
      exploitPath: v.exploitPath as string | undefined,
      // Unrecognized names are dropped rather than rejected: a mistyped ground
      // must not cost the whole fold, and the missing-ground report will show it.
      brocard: (BROCARDS as readonly string[]).includes(v.brocard as string) ? (v.brocard as Brocard) : undefined,
    }),
  });
}
