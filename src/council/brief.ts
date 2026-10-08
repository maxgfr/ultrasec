import type { Finding, Severity } from "../types.js";
import { SEVERITIES } from "../types.js";
import { stageNotes } from "../util.js";
import { LANGS, LOCALES, type Lang, type Phase } from "./locale.js";
import { redactReviewerText } from "./redact.js";
import { BRIEF_PREFIX } from "./snapshot.js";

// The brief every reviewer reads — the SAME text for every model, so their
// reports can be parsed by one parser and compared claim for claim.
//
// It is written to a file inside the snapshot and the CLI is given a one-line
// pointer to it. On the audit this came from, a ~60 KB prompt passed as one
// argv element hung a reviewer CLI at init for eleven minutes; and the brief
// quotes the run's own findings, which name attacker-controlled paths — the
// same reason powered mode never interpolates a worklist into a command line.
// Its text comes from the locale table (`locale.ts`).

export type { Lang, Phase };
export { LANGS };
export const PHASES: readonly Phase[] = ["blind", "devil"];

/** One line of the devil's-advocate list: identity, status and where — never the
 *  message or an evidence line, which is where secrets and attacker text live. */
export interface DevilItem {
  id: string;
  severity: Severity;
  status: string;
  title: string;
  at: string[];
}

export interface RejectedItem {
  id: string;
  title: string;
  reason: string;
}

const MAX_DEVIL_ITEMS = 300;
const MAX_REJECTED = 150;
const MAX_CONTEXT_CHARS = 6000;

export function briefName(phase: Phase, reviewer: string): string {
  return `${BRIEF_PREFIX}.${phase}.${reviewer}.md`;
}

/** Every cited location of a finding, in reading order, de-duplicated. */
export function findingCitations(f: Finding): string[] {
  const locs = [f.source, ...(f.path ?? []), f.sink, ...(f.locations ?? [])].filter((l): l is { file: string; line?: number } => !!l && !!l.file);
  const out: string[] = [];
  for (const l of locs) {
    const at = l.line ? `${l.file}:${l.line}` : l.file;
    if (!out.includes(at)) out.push(at);
  }
  return out;
}

const sevRank = (s: Severity): number => SEVERITIES.indexOf(s);

/**
 * The consolidated list a devil's advocate attacks: the run's confirmed and
 * needs-human findings (id, severity, status, title, first three citations),
 * plus what was already rejected and why — so a reviewer spends its budget on
 * what is still standing, and does not re-raise what was argued down without
 * new evidence.
 */
export function buildDevilList(
  findings: readonly Finding[],
  councilRejected: readonly RejectedItem[] = [],
): { items: DevilItem[]; rejected: RejectedItem[]; truncated: number } {
  const standing = findings
    .filter((f) => f.status === "confirmed" || f.status === "needs-human")
    .sort((a, b) => sevRank(a.severity) - sevRank(b.severity) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const items = standing.slice(0, MAX_DEVIL_ITEMS).map((f) => ({
    id: f.id,
    severity: f.severity,
    status: f.status,
    title: redactReviewerText(f.title),
    at: findingCitations(f).slice(0, 3),
  }));
  // Adjudicated dismissals only — an advisory nobody read was not "rejected".
  const dismissed = findings
    .filter((f) => f.status === "dismissed" && f.verdict && f.category !== "dep")
    .slice(0, MAX_REJECTED)
    .map((f) => ({
      id: f.id,
      title: redactReviewerText(f.title),
      reason: redactReviewerText([f.brocard, f.verdict, stageNotes(f.message)].filter(Boolean).join(" · ")).slice(0, 200),
    }));
  return {
    items,
    rejected: [...dismissed, ...councilRejected.map((r) => ({ ...r, title: redactReviewerText(r.title), reason: redactReviewerText(r.reason) }))],
    truncated: Math.max(0, standing.length - MAX_DEVIL_ITEMS),
  };
}

/** The short argv message: a pointer to the brief, and nothing attacker-influenced. */
export function argvMessage(lang: Lang, phase: Phase, reviewer: string): string {
  return LOCALES[lang].argv(briefName(phase, reviewer));
}

/** The one-turn closing message for a run cut before it wrote its report. */
export function finalizeMessage(lang: Lang, phase: Phase, reviewer: string): string {
  const l = LOCALES[lang];
  return l.finalize(briefName(phase, reviewer), l.headings.coverage);
}

export interface BriefInput {
  lang: Lang;
  phase: Phase;
  commit: string;
  focus?: string;
  context?: string;
  devil?: { items: DevilItem[]; rejected: RejectedItem[]; truncated: number };
}

export function renderBrief(b: BriefInput): string {
  const s = LOCALES[b.lang];
  const h = s.headings;
  const L: string[] = [`# ${s.title[b.phase]}`, "", s.intro[b.phase], ""];
  for (const r of s.rules) L.push(`- ${r.replace("{commit}", b.commit.slice(0, 12))}`);
  L.push("", b.focus ? s.focus(b.focus) : s.noFocus, "");
  if (b.context?.trim()) {
    const ctx = redactReviewerText(b.context.trim());
    L.push(`## ${s.trust}`, "", ctx.length > MAX_CONTEXT_CHARS ? `${ctx.slice(0, MAX_CONTEXT_CHARS)}\n…` : ctx, "");
  }
  if (b.phase === "devil" && b.devil) {
    L.push(`## ${s.list}`, "");
    for (const i of b.devil.items)
      L.push(`- \`${i.id}\` · ${i.severity} · ${i.status} · ${i.title}${i.at.length ? ` · ${i.at.map((a) => `\`${a}\``).join(", ")}` : ""}`);
    if (!b.devil.items.length) L.push("- (none)");
    if (b.devil.truncated) L.push(`- ${s.truncated(b.devil.truncated)}`);
    L.push("", `## ${s.rejected}`, "");
    for (const r of b.devil.rejected) L.push(`- \`${r.id}\` · ${r.title} — ${r.reason || "?"}`);
    if (!b.devil.rejected.length) L.push("- (none)");
    L.push("");
  }
  L.push(`## ${s.contract}`, "");
  // Section letters are language-neutral, so the parser finds a devil's
  // advocate's sections whatever language it answered in.
  if (b.phase === "devil")
    L.push(
      `## A. ${h.contested}`,
      s.contestedBody,
      "",
      `## B. ${h.newFindings}`,
      s.newFindingsBody,
      "",
      `## C. ${h.coverage}`,
      s.coverageBody,
      "",
      s.findingBlock,
      "",
    );
  else L.push(s.findingBlock, "", `## ${h.toVerify}`, s.toVerifyBody, "", `## ${h.coverage}`, s.coverageBody, "");
  return L.join("\n");
}
