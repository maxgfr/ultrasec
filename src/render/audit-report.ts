import { locationsLine, type Dossier } from "../store.js";
import { BROCARD_SUMMARY, SEVERITIES, type Finding, type Narrative, type Remediation, type Severity } from "../types.js";
import { compareWithinStatus, rankScore } from "../rank.js";
import { groupFamilies, pathRoot } from "../family.js";
import { byStr, engineProse, stageNotes } from "../util.js";
import { AI_DISCLAIMER, remediationMap } from "../narrative.js";
import { buildCoverage, enumeratedKindsOf, owaspTop10Of, renderCoverageMd } from "../coverage.js";
import { groupAdvisoriesByPackage, type PackageRow } from "../deps.js";
import { surfaceOf, unadjudicatedCode } from "../surface.js";
import type { Ledger } from "../council/ledger.js";
import { badgeOf, pathLine, provTag, riskTag, tierTable } from "./report.js";
import { headingSlug } from "./md-html.js";

// THE report: one Markdown file (or its HTML rendering) that carries the whole
// audit, in the order a reader acts on it.
//
// ── Why this replaced SUMMARY.md + REPORT.md + index.html ──────────────────
//
// On a 1,245-candidate monorepo run the old trio weighed ~2 MB, and REPORT.md
// alone was 746 KB — most of it one table row per DISMISSED candidate. It still
// lacked what the people fixing things needed: per finding "who attacks, what
// they send, what they get", the fix, the effort, a priority, a plan. The
// auditor ended up hand-writing a 255 KB report with a generator of their own.
// That hand-written layout is the one this renders:
//
//   1 executive summary · 2 dashboard · 3 attack chains · 4 follow-up vs a
//   previous audit · 5 detailed findings (by severity, then area) · 6 secrets ·
//   7 CI/CD & infra · 8 dependencies (one row per package) · 9 hardening ·
//   10 coverage & limits · 11 prioritized remediation plan · annexes A
//   dismissed (SUMMARISED), B needs-human, C engines & usage, D revalidation.
//
// ── Size discipline ────────────────────────────────────────────────────────
//
// What a reader acts on is printed in full; what they only need to be able to
// CHECK is summarised and every summary names how to get the rest. Dismissals
// are counted by ground and family, with the high-severity ones listed; a
// confirmed family lists its first locations and a count; advisories fold one
// row per package. `--full` restores every exhaustive table. Every finding is
// still in findings.json with its own id — summarising is presentation, never a
// decision (the same rule family.ts and deps.ts state).
//
// ── Never "no issues" by omission ──────────────────────────────────────────
//
// A report whose code candidates nobody read says DRAFT at the top, with why,
// and its status line repeats it. The engine's exit code is gone once the file
// is shared; the banner is what travels.

export interface AuditReportOptions {
  narrative?: Narrative;
  /** `<run>/council/COUNCIL.json`, when a council ran — usage + rejections in annex C. */
  council?: Ledger;
  /** Restore every exhaustive table (all dismissals, all undecided, all locations…). */
  full?: boolean;
  /** Result of the citation gate, when the caller ran it. Absent ⇒ "not checked". */
  grounding?: { ok: boolean; dangling: number };
  /** Files a finished run keeps — listed in annex C so a reader knows what exists. */
  artifacts?: string[];
}

/** Locations listed on a family card before "and N more". */
const LOC_CAP = 10;
/** High/critical dismissals listed one per line in annex A. */
const TOP_DISMISSED = 15;
/** Undecided HIGH+ code candidates listed by name. */
const UNDECIDED_TOP = 20;
/** Families named in a summary table. */
const FAMILY_TOP = 15;
/** Needs-human lines in annex B. */
const NEEDS_HUMAN_CAP = 150;
/** Packages in the dependency table. */
const PACKAGE_CAP = 100;
/** Checklist items per priority bucket. */
const PLAN_CAP = 40;
/** Rows in the by-area dashboard. */
const AREA_ROWS = 15;

export type Priority = "P0" | "P1" | "P2" | "P3";
const PRIORITIES: readonly Priority[] = ["P0", "P1", "P2", "P3"];
const PRIORITY_TITLE: Record<Priority, string> = {
  P0: "P0 — fix now",
  P1: "P1 — this sprint",
  P2: "P2 — planned",
  P3: "P3 — opportunistic",
};

const SEV_WORD: Record<Severity, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };

// ── Status ──────────────────────────────────────────────────────────────────

export interface ReportStatus {
  draft: boolean;
  /** Why it is a draft — each one a sentence a reader can act on. */
  reasons: string[];
  /** Whether the citation gate ran and passed; undefined when it could not run. */
  grounded?: boolean;
}

/**
 * Whether the run is a finished audit or a DRAFT. A draft when HIGH/CRITICAL
 * code candidates were never read, when a required scanner did not complete,
 * when a cited location does not resolve, or when nothing at all was
 * adjudicated while code/config candidates exist — the four ways a report can
 * look finished and not be.
 */
export function reportStatus(d: Dossier, grounding?: AuditReportOptions["grounding"]): ReportStatus {
  const reasons: string[] = [];
  const unread = unadjudicatedCode(d.findings);
  if (unread.length) {
    const crit = unread.filter((f) => f.severity === "critical").length;
    reasons.push(`${unread.length} HIGH/CRITICAL source-code candidate(s) never read${crit ? ` (${crit} critical)` : ""}`);
  }
  const policy = d.manifest.scannerPolicy;
  if (policy && !policy.complete) reasons.push(`required scanner(s) did not complete: ${policy.incomplete.join(", ")}`);
  if (grounding && !grounding.ok) reasons.push(`${grounding.dangling} cited location(s) do not resolve (\`check\` failed)`);
  const ownOpen = d.findings.some((f) => f.status === "open" && surfaceOf(f) !== "deps");
  if (ownOpen && !d.findings.some((f) => f.status !== "open")) reasons.push("no candidate has been adjudicated yet");
  return { draft: reasons.length > 0, reasons, ...(grounding ? { grounded: grounding.ok } : {}) };
}

/** The one-line status `audit` prints and the report opens with. */
export function statusLine(d: Dossier, s: ReportStatus): string {
  const n = (st: Finding["status"]) => d.findings.filter((f) => f.status === st).length;
  const tally = `${n("confirmed")} confirmed · ${n("needs-human")} needs human · ${n("open")} undecided · ${n("dismissed")} dismissed`;
  if (s.draft) return `DRAFT — ${s.reasons.join("; ")} (${tally})`;
  return `${s.grounded ? "adjudicated & grounded" : "adjudicated (citations not checked — the audited tree is not here)"} — ${tally}`;
}

// ── Small helpers ───────────────────────────────────────────────────────────

function primaryFile(f: Finding): string | undefined {
  return f.path?.[0]?.file ?? f.sink?.file ?? f.source?.file ?? f.locations?.[0]?.file;
}

/**
 * The area a file belongs to: the deepest detected package directory that
 * contains it (the stack table records one per workspace), else its first two
 * directory segments — the same root `family.ts` keys on, so a monorepo's
 * `apps/web` and `apps/api` stay apart without naming any of them here.
 */
export function areaOf(file: string | undefined, workspaces: readonly string[]): string {
  if (!file) return "(unplaced)";
  let best = "";
  for (const w of workspaces) if (w && (file === w || file.startsWith(`${w}/`)) && w.length > best.length) best = w;
  if (best) return best;
  const root = pathRoot(file);
  return root === "." ? "(root)" : root;
}

function workspacesOf(d: Dossier): string[] {
  return [...new Set((d.manifest.frameworks ?? []).map((f) => f.dir).filter((x): x is string => Boolean(x)))];
}

/** One line, at most `n` characters — a summary cell, never a paragraph. */
function oneLine(s: string, n: number): string {
  const flat = s.replace(/\s+/g, " ").trim();
  return flat.length > n ? `${flat.slice(0, n - 1).trimEnd()}…` : flat;
}

/** Make a string safe inside a Markdown table cell. */
function cell(s: string): string {
  return s.replace(/\|/g, "\\|").replace(/\n+/g, " ");
}

function priorityOf(f: Finding): Priority {
  if (f.status === "needs-human") return f.severity === "critical" || f.severity === "high" ? "P1" : "P2";
  if (f.severity === "critical") return "P0";
  if (f.severity === "high") return f.kev || f.verified ? "P0" : "P1";
  if (f.severity === "medium") return "P2";
  return "P3";
}

function packagePriority(r: PackageRow): Priority {
  const runtime = r.reachability !== "toolchain";
  if (r.kev && runtime) return "P0";
  if ((r.worst === "critical" || r.worst === "high") && runtime) return "P1";
  if (r.worst === "critical" || r.worst === "high" || r.worst === "medium") return "P2";
  return "P3";
}

/** The ground a dismissal stands on, as one key: named brocard, fix, triage, or none. */
function groundOf(f: Finding): string {
  if (f.brocard) return f.brocard;
  if (f.fixedIn || /Revalidation \(fixed\)/.test(f.message)) return "fixed (revalidation)";
  if (/Triage: /.test(f.message)) return "triage: noise";
  if (f.verdict === "refuted") return "refuted — no named ground";
  return "dismissed — no ground recorded";
}

const GROUND_GLOSS = (g: string): string => (Object.hasOwn(BROCARD_SUMMARY, g) ? BROCARD_SUMMARY[g as keyof typeof BROCARD_SUMMARY] : "");

/** "a, b and 3 more" — the cap every summary cell uses. */
function capList(items: readonly string[], n: number): string {
  if (items.length <= n) return items.join(", ");
  return `${items.slice(0, n).join(", ")} and ${items.length - n} more`;
}

/** Whatever revalidation says about a finding, from its stage note. */
function revalidationOf(f: Finding): string | undefined {
  const m = /Revalidation \(([^)]+)\)/.exec(f.message);
  if (m) return m[1];
  return f.fixedIn ? "fixed" : undefined;
}

function countBy<T>(items: readonly T[], key: (t: T) => string): [string, number][] {
  const m = new Map<string, number>();
  for (const it of items) m.set(key(it), (m.get(key(it)) ?? 0) + 1);
  return [...m.entries()].sort((a, b) => b[1] - a[1] || byStr(a[0], b[0]));
}

const slug = headingSlug;

const SECTIONS = [
  "1. Executive summary",
  "2. Dashboard",
  "3. Attack chains",
  "4. Follow-up vs previous audit",
  "5. Detailed findings",
  "6. Secrets & history",
  "7. CI/CD & infrastructure exposure",
  "8. Dependencies",
  "9. Hardening notes",
  "10. Coverage & limits",
  "11. Remediation plan",
  "Annex A — Dismissed candidates",
  "Annex B — Needs human review",
  "Annex C — Engines & usage",
  "Annex D — Revalidation table",
] as const;

// ── The report ──────────────────────────────────────────────────────────────

export function renderAuditReport(d: Dossier, opts: AuditReportOptions = {}): string {
  const ctx = makeContext(d, opts);
  const status = reportStatus(d, opts.grounding);
  const L: string[] = [];
  L.push(`# Security audit report`, "");
  L.push(
    `\`${d.manifest.repo}\` · ultrasec ${d.manifest.version} · ${d.findings.length} candidate(s) · ${opts.grounding ? (opts.grounding.ok ? "citations resolve" : "**citations DO NOT resolve**") : "citations not checked"}`,
    "",
  );
  L.push(`**Status:** ${status.draft ? "⚠️ " : "✅ "}${statusLine(d, status)}`, "");
  if (status.draft) L.push(...draftBanner(status));
  L.push(
    `**Contents:** ${SECTIONS.filter((s) => s !== "Annex D — Revalidation table" || (opts.full && ctx.revalidated.length))
      .map((s) => `[${s}](#${slug(s)})`)
      .join(" · ")}`,
    "",
  );

  L.push(...executiveSummary(d, ctx, status));
  L.push(...dashboard(d, ctx));
  L.push(...attackChains(ctx));
  L.push(...followUp(ctx));
  L.push(...detailedFindings(ctx));
  L.push(...secretsSection(ctx));
  L.push(...cicdSection(ctx));
  L.push(...dependencySection(ctx));
  L.push(...hardeningSection(ctx));
  L.push(...coverageSection(d));
  L.push(...remediationPlan(ctx, status));
  L.push(...annexDismissed(ctx));
  L.push(...annexNeedsHuman(ctx));
  L.push(...annexEngines(d, opts));
  if (opts.full && ctx.revalidated.length) L.push(...annexRevalidation(ctx));
  L.push(`---`, "");
  L.push(
    `_Engine: ultrasec ${d.manifest.version}. ${d.manifest.generatedNote} Every finding keeps its own id in \`findings.json\`; this report groups and summarises, it never merges or decides.${opts.full ? "" : " Exhaustive annexes: `ultrasec render --full`."}_`,
  );
  return L.join("\n") + "\n";
}

interface Ctx {
  full: boolean;
  narrative?: Narrative;
  rem: Map<string, Remediation>;
  areaOf: (f: Finding) => string;
  areaOfFile: (file: string | undefined) => string;
  /** Confirmed + needs-human, per surface. */
  code: Finding[];
  secrets: Finding[];
  config: Finding[];
  deps: Finding[];
  undecidedCode: Finding[];
  dismissed: Finding[];
  needs: Finding[];
  revalidated: Finding[];
  all: Finding[];
}

function makeContext(d: Dossier, opts: AuditReportOptions): Ctx {
  const ws = workspacesOf(d);
  const live = d.findings.filter((f) => f.status === "confirmed" || f.status === "needs-human");
  return {
    full: !!opts.full,
    narrative: opts.narrative,
    rem: remediationMap(opts.narrative),
    areaOf: (f) => areaOf(primaryFile(f), ws),
    areaOfFile: (file) => areaOf(file, ws),
    code: live.filter((f) => surfaceOf(f) === "code").sort(compareWithinStatus),
    secrets: d.findings.filter((f) => f.category === "secret" && f.status !== "dismissed").sort(compareWithinStatus),
    config: d.findings.filter((f) => surfaceOf(f) === "supply" && f.category !== "secret" && f.status !== "dismissed").sort(compareWithinStatus),
    deps: d.findings.filter((f) => surfaceOf(f) === "deps" && f.status !== "dismissed").sort(compareWithinStatus),
    undecidedCode: d.findings.filter((f) => f.status === "open" && surfaceOf(f) === "code").sort(compareWithinStatus),
    dismissed: d.findings.filter((f) => f.status === "dismissed").sort(compareWithinStatus),
    needs: d.findings.filter((f) => f.status === "needs-human").sort(compareWithinStatus),
    revalidated: d.findings.filter((f) => revalidationOf(f) !== undefined).sort(compareWithinStatus),
    all: d.findings,
  };
}

function draftBanner(s: ReportStatus): string[] {
  const L = [`> ## ⚠️ DRAFT — this is not a finished audit`, `>`];
  for (const r of s.reasons) L.push(`> - ${r}`);
  L.push(
    `>`,
    `> Nothing below may be read as "no issues": an undecided candidate is **undecided**, not **safe**.`,
    `> Finish it: \`ultrasec audit --repo <repo> --out <run> --keep-work\` keeps the JSON worklists; adjudicate`,
    `> (\`ultrasec paths --run <run> --surface code\` → \`ultrasec dossier <id> --run <run>\` → \`ultrasec verify --apply verdicts.json --run <run>\`),`,
    `> then \`ultrasec render --run <run>\`. Or let an agent CLI do it: \`ultrasec audit --repo <repo> --powered <cli>\`.`,
    "",
  );
  return L;
}

// ── 1. Executive summary ────────────────────────────────────────────────────

function executiveSummary(d: Dossier, ctx: Ctx, status: ReportStatus): string[] {
  const L = [`## ${SECTIONS[0]}`, ""];
  if (ctx.narrative?.executiveSummary) L.push(`_${AI_DISCLAIMER}_`, "", ctx.narrative.executiveSummary, "");
  const confirmed = d.findings.filter((f) => f.status === "confirmed");
  const bySev = (fs: Finding[]) =>
    SEVERITIES.map((s) => [s, fs.filter((f) => f.severity === s).length] as const)
      .filter(([, n]) => n)
      .map(([s, n]) => `${n} ${s}`)
      .join(", ");
  if (confirmed.length) {
    L.push(
      `**${confirmed.length} confirmed** (${bySev(confirmed)}), **${ctx.needs.length} awaiting a human decision**, out of ${d.findings.length} candidates.`,
      "",
    );
    const top = groupFamilies(confirmed.filter((f) => surfaceOf(f) !== "deps")).families.map((fam) => ({ f: fam.lead, n: fam.members.length }));
    const singles = groupFamilies(confirmed.filter((f) => surfaceOf(f) !== "deps")).singles.map((f) => ({ f, n: 1 }));
    const ranked = [...top, ...singles].sort((a, b) => compareWithinStatus(a.f, b.f)).slice(0, 5);
    if (ranked.length) {
      L.push(`Most urgent:`, "");
      for (const r of ranked) L.push(`- ${badgeOf(r.f.severity)} ${r.f.title}${r.n > 1 ? ` ×${r.n}` : ""} — ${ctx.areaOf(r.f)} (\`${r.f.id}\`)`);
      L.push("");
    }
  } else if (status.draft) {
    L.push(`**Nothing is confirmed because nothing was decided** — ${d.findings.length} candidate(s), see the status above.`, "");
  } else if (d.findings.length) {
    L.push(
      `**No confirmed issue** among ${d.findings.length} adjudicated candidate(s), in what this audit looked at — see [10. Coverage & limits](#${slug(SECTIONS[9])}).`,
      "",
    );
  } else {
    L.push(`**No candidate** was produced — see [10. Coverage & limits](#${slug(SECTIONS[9])}) for what that does and does not mean.`, "");
  }
  const ext = d.manifest.extraction;
  if (ext && !ext.ast) L.push(`> ⚠️ Degraded run: tree-sitter was unavailable, the regex extractors ran — fewer cross-file flows than a full run.`, "");
  if (d.manifest.truncation?.candidates)
    L.push(`> ⚠️ Capped: ${d.manifest.truncation.candidates} of ${d.manifest.truncation.total} candidates were not enumerated.`, "");
  return L;
}

// ── 2. Dashboard ────────────────────────────────────────────────────────────

function dashboard(d: Dossier, ctx: Ctx): string[] {
  const L = [`## ${SECTIONS[1]}`, ""];
  const by = (sev: Severity, st: Finding["status"]) => d.findings.filter((f) => f.severity === sev && f.status === st).length;
  L.push(`| severity | confirmed | needs human | undecided | dismissed | total |`, `|---|---|---|---|---|---|`);
  for (const s of SEVERITIES) {
    const row = [by(s, "confirmed"), by(s, "needs-human"), by(s, "open"), by(s, "dismissed")];
    L.push(`| ${badgeOf(s)} | ${row.join(" | ")} | ${row.reduce((a, b) => a + b, 0)} |`);
  }
  L.push("");
  const surfaceRow = (name: string, fs: Finding[]) => {
    const n = (st: Finding["status"]) => fs.filter((f) => f.status === st).length;
    return `| ${name} | ${n("confirmed")} | ${n("needs-human")} | ${n("open")} | ${n("dismissed")} |`;
  };
  L.push(`| surface | confirmed | needs human | undecided | dismissed |`, `|---|---|---|---|---|`);
  L.push(
    surfaceRow(
      "source code",
      d.findings.filter((f) => surfaceOf(f) === "code"),
    ),
  );
  L.push(
    surfaceRow(
      "secrets",
      d.findings.filter((f) => f.category === "secret"),
    ),
  );
  L.push(
    surfaceRow(
      "CI/CD & infra",
      d.findings.filter((f) => surfaceOf(f) === "supply" && f.category !== "secret"),
    ),
  );
  L.push(
    surfaceRow(
      "dependencies",
      d.findings.filter((f) => surfaceOf(f) === "deps"),
    ),
  );
  L.push("");
  const live = d.findings.filter((f) => f.status !== "dismissed");
  const areas = new Map<string, Finding[]>();
  for (const f of live) {
    const a = ctx.areaOf(f);
    const list = areas.get(a);
    if (list) list.push(f);
    else areas.set(a, [f]);
  }
  if (areas.size) {
    const rows = [...areas.entries()]
      .map(([area, fs]) => ({ area, fs, decided: fs.filter((f) => f.status !== "open") }))
      .sort((a, b) => b.decided.length - a.decided.length || b.fs.length - a.fs.length || byStr(a.area, b.area));
    L.push(`By area (live candidates; areas are detected workspaces, else the first two path segments):`, "");
    L.push(`| area | critical | high | medium | low/info | of which decided | undecided |`, `|---|---|---|---|---|---|---|`);
    const shown = ctx.full ? rows : rows.slice(0, AREA_ROWS);
    for (const r of shown) {
      const n = (sev: Severity[]) => r.fs.filter((f) => sev.includes(f.severity)).length;
      L.push(
        `| \`${r.area}\` | ${n(["critical"])} | ${n(["high"])} | ${n(["medium"])} | ${n(["low", "info"])} | ${r.decided.length} | ${r.fs.length - r.decided.length} |`,
      );
    }
    if (shown.length < rows.length) L.push(`| _${rows.length - shown.length} more area(s)_ | | | | | | |`);
    L.push("");
  }
  return L;
}

// ── 3. Attack chains ────────────────────────────────────────────────────────

function attackChains(ctx: Ctx): string[] {
  const L = [`## ${SECTIONS[2]}`, ""];
  const chains = ctx.narrative?.attackChains ?? [];
  if (!chains.length) {
    L.push(`_None recorded. Chains are authored in NARRATIVE.json (\`attackChains\`) from confirmed findings._`, "");
    return L;
  }
  const byId = new Map(ctx.all.map((f) => [f.id, f]));
  L.push(`_${AI_DISCLAIMER}_`, "");
  for (const c of chains) {
    L.push(`### ${c.title}`, "");
    L.push(`Steps: ${c.findingIds.map((id) => `${byId.get(id)?.title ?? "?"} (\`${id}\`)`).join(" → ")}`, "");
    L.push(c.narrative, "");
  }
  return L;
}

// ── 4. Follow-up ────────────────────────────────────────────────────────────

function followUp(ctx: Ctx): string[] {
  const L = [`## ${SECTIONS[3]}`, ""];
  if (!ctx.revalidated.length) {
    L.push(`_No revalidation data. \`ultrasec revalidate\` against this run fills this section (fixed · still present · new)._`, "");
    return L;
  }
  const outcome = (f: Finding) => revalidationOf(f) ?? "";
  const fixed = ctx.revalidated.filter((f) => outcome(f) === "fixed");
  const still = ctx.revalidated.filter((f) => outcome(f) === "still-valid");
  const other = ctx.revalidated.filter((f) => !["fixed", "still-valid"].includes(outcome(f)));
  const fresh = ctx.all.filter((f) => (f.status === "confirmed" || f.status === "needs-human") && revalidationOf(f) === undefined);
  L.push(`| outcome | count | examples |`, `|---|---|---|`);
  const ex = (fs: Finding[]) =>
    cell(
      capList(
        fs.map((f) => `${f.title} (\`${f.id}\`)`),
        3,
      ),
    ) || "—";
  L.push(`| ✅ fixed | ${fixed.length} | ${ex(fixed)} |`);
  L.push(`| ⏳ still present | ${still.length} | ${ex(still)} |`);
  L.push(`| ❓ escalated / uncertain | ${other.length} | ${ex(other)} |`);
  L.push(`| 🆕 new since (not revalidated) | ${fresh.length} | ${ex(fresh)} |`);
  L.push("");
  if (!ctx.full) L.push(`_Per-finding table: \`render --full\` (annex D)._`, "");
  return L;
}

// ── 5. Detailed findings ────────────────────────────────────────────────────

interface Card {
  lead: Finding;
  members: Finding[];
}

function cardsOf(findings: readonly Finding[]): Card[] {
  const g = groupFamilies(findings);
  return [...g.families.map((fam) => ({ lead: fam.lead, members: fam.members })), ...g.singles.map((f) => ({ lead: f, members: [f] }))].sort((a, b) =>
    compareWithinStatus(a.lead, b.lead),
  );
}

function detailedFindings(ctx: Ctx): string[] {
  const L = [`## ${SECTIONS[4]}`, ""];
  if (!ctx.code.length) {
    L.push(`_No confirmed or needs-human finding in this repository's own code._`, "");
  } else {
    L.push(`Confirmed and needs-human findings in this repository's own code, by severity then area. A repeated finding is one card.`, "");
    let n = 0;
    for (const sev of SEVERITIES) {
      const cards = cardsOf(ctx.code.filter((f) => f.severity === sev));
      if (!cards.length) continue;
      n++;
      L.push(`### 5.${n} ${SEV_WORD[sev]} (${cards.reduce((a, c) => a + c.members.length, 0)})`, "");
      const byArea = new Map<string, Card[]>();
      for (const c of cards) {
        const a = ctx.areaOf(c.lead);
        const list = byArea.get(a);
        if (list) list.push(c);
        else byArea.set(a, [c]);
      }
      for (const area of [...byArea.keys()].sort(byStr)) {
        L.push(`#### Area \`${area}\``, "");
        for (const c of byArea.get(area)!) L.push(...renderCard(c, ctx));
      }
    }
  }
  L.push(...undecidedCode(ctx));
  return L;
}

function locationOf(f: Finding): string {
  if (f.locations?.length) return locationsLine(f.locations);
  return pathLine(f);
}

function renderCard(c: Card, ctx: Ctx): string[] {
  const f = c.lead;
  const pri = priorityOf(f);
  const rem = c.members.map((m) => ctx.rem.get(m.id)).find(Boolean);
  const owasp = owaspTop10Of(f);
  const sources = (f.sources?.length ? f.sources : [f.tool]).join(", ");
  const meta = [
    `\`${f.id}\``,
    `area \`${ctx.areaOf(f)}\``,
    f.cwe ?? f.category,
    owasp ? `OWASP ${owasp.id} ${owasp.title}` : "",
    `priority **${pri}**`,
    `effort ${rem?.effort ?? "—"}`,
    `${f.status}${f.verdict ? ` (${f.verdict})` : ""}`,
    `found by ${sources}`,
  ].filter(Boolean);
  const L = [
    `##### ${badgeOf(f.severity)} ${f.vulnClass ? `${f.title} [${f.vulnClass}]` : f.title}${c.members.length > 1 ? ` ×${c.members.length}` : ""}`,
    "",
    meta.join(" · "),
    "",
  ];
  if (c.members.length === 1) {
    L.push(`- **Where:** ${locationOf(f)}`);
  } else {
    const shown = ctx.full ? c.members : c.members.slice(0, LOC_CAP);
    L.push(`- **Where (${c.members.length} occurrences):**`);
    for (const m of shown) L.push(`  - ${locationOf(m)} \`${m.id}\``);
    if (shown.length < c.members.length) L.push(`  - _…and ${c.members.length - shown.length} more (\`render --full\`, or \`ultrasec paths --run <run>\`)_`);
  }
  const scenario = c.members.map((m) => m.exploitPath).find(Boolean);
  if (scenario) L.push(`- **Attacker scenario:** ${scenario.replace(/\n+/g, " ")}`);
  else if (f.status === "needs-human") L.push(`- **Attacker scenario:** _not established — that is why it needs a human (see notes)._`);
  else L.push(`- **Attacker scenario:** _not recorded — add an \`exploitPath\` to the verdict._`);
  if (rem) {
    L.push(`- **Fix:** ${rem.fix.replace(/\n+/g, " ")}${rem.owner ? ` · owner ${rem.owner}` : ""}`);
    if (rem.patch) L.push("", "```diff", rem.patch.replace(/\n+$/, ""), "```", "");
  } else if (f.status === "confirmed") {
    L.push(`- **Fix:** _not authored — add it to NARRATIVE.json \`remediations\`._`);
  }
  const notes = [stageNotes(f.message), f.brocard ? `ground: ${f.brocard}` : "", riskTag(f), provTag(f) ? `provenance ${provTag(f)}` : ""].filter(Boolean);
  if (notes.length) L.push(`- **Notes:** ${notes.join(" · ").replace(/\n+/g, " ")}`);
  if (f.category !== "secret") {
    const prose = engineProse(f.message);
    if (prose) L.push(`- **Evidence:** ${oneLine(prose, 300)}`);
  }
  L.push("");
  return L;
}

function familySummary(fs: readonly Finding[], ctx: Ctx, n: number): string[] {
  const groups = countBy(fs, (f) => f.vulnClass ?? f.title);
  const L = [`| candidate shape | count | areas |`, `|---|---|---|`];
  const shown = ctx.full ? groups : groups.slice(0, n);
  for (const [title, count] of shown) {
    const areas = [...new Set(fs.filter((f) => (f.vulnClass ?? f.title) === title).map(ctx.areaOf))].sort(byStr);
    L.push(
      `| ${cell(oneLine(title, 90))} | ${count} | ${cell(
        capList(
          areas.map((a) => `\`${a}\``),
          3,
        ),
      )} |`,
    );
  }
  if (shown.length < groups.length)
    L.push(`| _${groups.length - shown.length} more shape(s)_ | ${groups.slice(shown.length).reduce((a, [, c]) => a + c, 0)} | |`);
  L.push("");
  return L;
}

function undecidedCode(ctx: Ctx): string[] {
  const open = ctx.undecidedCode;
  if (!open.length) return [];
  const L = [`### Undecided source-code candidates (${open.length})`, ""];
  L.push(`Recall-oriented engine output nobody has adjudicated yet — each is decided by opening the file (\`ultrasec dossier <id>\`), not from this list.`, "");
  if (ctx.full) {
    L.push(...tierTable(open), "");
    return L;
  }
  const high = open.filter((f) => f.severity === "critical" || f.severity === "high");
  if (high.length) {
    L.push(`HIGH/CRITICAL first${high.length > UNDECIDED_TOP ? ` (top ${UNDECIDED_TOP} of ${high.length} by risk)` : ""}:`, "");
    for (const f of high.slice(0, UNDECIDED_TOP)) L.push(`- ${badgeOf(f.severity)} ${f.title} — ${pathLine(f)} \`${f.id}\``);
    L.push("");
  }
  L.push(`By shape:`, "");
  L.push(...familySummary(open, ctx, FAMILY_TOP));
  return L;
}

// ── 6. Secrets / 7. CI-CD & infra ───────────────────────────────────────────

function classTable(fs: readonly Finding[], ctx: Ctx, withPriority: boolean): string[] {
  const groups = new Map<string, Finding[]>();
  for (const f of fs) {
    const list = groups.get(f.title);
    if (list) list.push(f);
    else groups.set(f.title, [f]);
  }
  const rows = [...groups.entries()].sort((a, b) => compareWithinStatus(a[1][0]!, b[1][0]!));
  const L = [`| ${withPriority ? "priority | " : ""}worst | class | verdicts | where |`, `|${withPriority ? "---|" : ""}---|---|---|---|`];
  const shown = ctx.full ? rows : rows.slice(0, FAMILY_TOP * 2);
  for (const [title, members] of shown) {
    const st = countBy(members, (f) => f.status)
      .map(([s, n]) => `${n} ${s}`)
      .join(" · ");
    const verified = members.some((f) => f.verified) ? " · ✅ verified live" : "";
    const where = members.map((f) => `${locationOf(f)}`);
    const cap = ctx.full ? where.length : 3;
    const lead = members[0]!;
    L.push(
      `| ${withPriority ? `${priorityOf(lead)} | ` : ""}${badgeOf(lead.severity)} | ${cell(oneLine(title, 100))} | ${st}${verified} | ${cell(capList(where, cap))} |`,
    );
  }
  if (shown.length < rows.length) L.push(`| ${withPriority ? " | " : ""} | _${rows.length - shown.length} more class(es) — \`render --full\`_ | | |`);
  L.push("");
  return L;
}

/** Cards for the decided (confirmed / needs-human) members of a supply-side surface. */
function decidedCards(fs: readonly Finding[], ctx: Ctx): string[] {
  const decided = fs.filter((f) => f.status === "confirmed" || f.status === "needs-human");
  if (!decided.length) return [];
  const L: string[] = [];
  for (const c of cardsOf(decided)) L.push(...renderCard(c, ctx));
  return L;
}

function secretsSection(ctx: Ctx): string[] {
  const L = [`## ${SECTIONS[5]}`, ""];
  const dismissed = ctx.dismissed.filter((f) => f.category === "secret");
  if (!ctx.secrets.length) {
    L.push(`_No live secret finding._${dismissed.length ? ` ${dismissed.length} dismissed (annex A).` : ""}`, "");
  } else {
    L.push(`Values are never printed here — locations only; the engine masks what it quotes. One row per detector class.`, "");
    L.push(...classTable(ctx.secrets, ctx, true));
    L.push(...decidedCards(ctx.secrets, ctx));
    if (dismissed.length) L.push(`_${dismissed.length} secret candidate(s) dismissed — grounds in annex A._`, "");
  }
  const history = ctx.all.length ? historyNote(ctx) : "";
  if (history) L.push(history, "");
  return L;
}

/** What the secret scanners saw of git history — "not scanned" is a coverage fact. */
function historyNote(ctx: Ctx): string {
  const fromHistory = ctx.all.filter((f) => f.atCommit && f.category === "secret").length;
  return fromHistory ? `**History:** ${fromHistory} secret finding(s) cite a past commit — rotate them even if the file is gone.` : "";
}

function cicdSection(ctx: Ctx): string[] {
  const L = [`## ${SECTIONS[6]}`, ""];
  if (!ctx.config.length) {
    L.push(`_No live CI/CD, IaC or configuration finding._`, "");
    return L;
  }
  L.push(`Workflows, infrastructure-as-code and security configuration — read as a diff, one row per class.`, "");
  L.push(...classTable(ctx.config, ctx, true));
  L.push(...decidedCards(ctx.config, ctx));
  return L;
}

// ── 8. Dependencies ─────────────────────────────────────────────────────────

function dependencySection(ctx: Ctx): string[] {
  const L = [`## ${SECTIONS[7]}`, ""];
  const rows = groupAdvisoriesByPackage(ctx.deps);
  const dismissed = ctx.dismissed.filter((f) => surfaceOf(f) === "deps").length;
  if (!rows.length) {
    L.push(`_No live dependency advisory._${dismissed ? ` ${dismissed} dismissed.` : ""}`, "");
    return L;
  }
  const ws = (r: PackageRow) => [...new Set(r.locations.map((l) => ctx.areaOfFile(l.file)))].sort(byStr);
  L.push(`One row per package — the unit you upgrade. KEV first, then EPSS, then severity; stop at your bar.`, "");
  L.push(
    `| priority | worst | package | installed | advisories | main advisory | upgrade to | runtime? | target | status |`,
    `|---|---|---|---|---|---|---|---|---|---|`,
  );
  const shown = ctx.full ? rows : rows.slice(0, PACKAGE_CAP);
  for (const r of shown) {
    const lead = r.advisories[0]!;
    const main = [
      lead.cve ?? lead.aliases?.[0] ?? oneLine(lead.title, 60),
      r.kev ? "🚨 KEV" : "",
      typeof r.maxEpss === "number" ? `EPSS ${(r.maxEpss * 100).toFixed(1)}%` : "",
    ]
      .filter(Boolean)
      .join(" · ");
    const runtime = r.reachability === "toolchain" ? "no (build/dev)" : r.reachability === "runtime" ? "yes" : "?";
    const versions = r.versions.length ? capList(r.versions, 3) : "—";
    const st = countBy(r.advisories, (f) => f.status)
      .map(([s, n]) => `${n} ${s}`)
      .join(" · ");
    L.push(
      `| ${packagePriority(r)} | ${badgeOf(r.worst)} | \`${r.pkg}\` | ${cell(versions)} | ${r.count} | ${cell(main)} | ${r.fixedVersion ?? "_no fix published_"} | ${runtime} | ${cell(
        capList(
          ws(r).map((a) => `\`${a}\``),
          2,
        ),
      )} | ${st} |`,
    );
  }
  if (shown.length < rows.length) L.push(`| | | _${rows.length - shown.length} more package(s), lower risk — \`render --full\`_ | | | | | | | |`);
  L.push("");
  if (dismissed) L.push(`_${dismissed} advisory(ies) dismissed — annex A._`, "");
  return L;
}

// ── 9. Hardening ────────────────────────────────────────────────────────────

function hardeningSection(ctx: Ctx): string[] {
  const L = [`## ${SECTIONS[8]}`, ""];
  const n = ctx.narrative;
  if (!n?.positivePatterns && !n?.hardeningNotes?.length) {
    L.push(`_None authored (NARRATIVE.json \`hardeningNotes\`, \`positivePatterns\`)._`, "");
    return L;
  }
  L.push(`_${AI_DISCLAIMER} Defense in depth — **not** findings, excluded from every count._`, "");
  if (n.positivePatterns) L.push(`**What the codebase does well:** ${n.positivePatterns}`, "");
  for (const note of n.hardeningNotes ?? []) L.push(`- ${note}`);
  if (n.hardeningNotes?.length) L.push("");
  return L;
}

// ── 10. Coverage ────────────────────────────────────────────────────────────

function coverageSection(d: Dossier): string[] {
  const L = [`## ${SECTIONS[9]}`, ""];
  const m = d.manifest;
  const limits: string[] = [];
  if (m.extraction && !m.extraction.ast) limits.push(`regex extraction tier (tree-sitter unavailable) — fewer cross-file flows`);
  if (m.truncation?.candidates) limits.push(`${m.truncation.candidates} of ${m.truncation.total} taint candidates not enumerated (cap)`);
  if (m.truncation?.files) limits.push(`file walk hit --max-files — some files were not scanned`);
  if (m.scopes?.length) limits.push(`scoped run — only ${m.scopes.map((s) => `\`${s}\``).join(", ")} analysed`);
  const failed = (m.toolStatus ?? []).filter((s) => s.status === "failed");
  const skipped = (m.toolStatus ?? []).filter((s) => s.status === "skipped");
  const degraded = (m.toolStatus ?? []).filter((s) => s.degraded && (s.status === "ran" || s.status === "empty"));
  if (failed.length) limits.push(`scanner(s) FAILED: ${failed.map((s) => s.name).join(", ")} — a hole, not an empty result`);
  if (degraded.length) limits.push(`degraded scanner pass: ${degraded.map((s) => `${s.name} (${s.degraded})`).join("; ")}`);
  if (!m.toolStatus?.length && !m.toolsRun.length) limits.push(`no external scanner ran — graph + taint only`);
  else if (skipped.length)
    limits.push(
      `${skipped.length} scanner(s) skipped (not installed / no target): ${capList(
        skipped.map((s) => s.name),
        8,
      )}`,
    );
  if (m.resolutionGaps?.length) limits.push(`imports not followed into ${m.resolutionGaps.map((g) => `${g.files} \`${g.ext}\``).join(", ")} file(s)`);
  if (m.notebooks?.note) limits.push(m.notebooks.note);
  limits.push(`static analysis only: no DAST, no fuzzing, no authenticated crawling, no runtime testing`);
  L.push(`**Not looked at / limits:**`, "");
  for (const l of limits) L.push(`- ${l}`);
  L.push("");
  // The ASVS matrix, headings demoted one level to sit under this section.
  const cov = renderCoverageMd(buildCoverage(d, enumeratedKindsOf(d.findings)), undefined, d)
    .split("\n")
    .map((line) => (/^#{2,5} /.test(line) ? `#${line}` : line));
  L.push(...cov);
  return L;
}

// ── 11. Remediation plan ────────────────────────────────────────────────────

function remediationPlan(ctx: Ctx, status: ReportStatus): string[] {
  const L = [`## ${SECTIONS[10]}`, ""];
  const items: Record<Priority, string[]> = { P0: [], P1: [], P2: [], P3: [] };
  if (status.draft) {
    const unread = unadjudicatedCode(ctx.all);
    if (unread.length)
      items.P0.push(`- [ ] **Adjudicate the ${unread.length} unread HIGH/CRITICAL code candidate(s)** — the findings above are incomplete until then.`);
  }
  const live = [...ctx.code, ...ctx.secrets.filter((f) => f.status !== "open"), ...ctx.config.filter((f) => f.status !== "open")];
  for (const c of cardsOf(live)) {
    const f = c.lead;
    const rem = c.members.map((m) => ctx.rem.get(m.id)).find(Boolean);
    const what = f.status === "needs-human" ? `Decide: ${f.title}` : `${f.title}${c.members.length > 1 ? ` ×${c.members.length}` : ""}`;
    const how = f.status === "needs-human" ? "" : rem ? ` — ${oneLine(rem.fix, 140)}${rem.effort ? ` (effort ${rem.effort})` : ""}` : " — fix not authored";
    items[priorityOf(f)].push(`- [ ] **${what}** · \`${ctx.areaOf(f)}\` · \`${f.id}\`${how}`);
  }
  for (const r of groupAdvisoriesByPackage(ctx.deps)) {
    const pri = packagePriority(r);
    items[pri].push(
      `- [ ] Upgrade \`${r.pkg}\`${r.fixedVersion ? ` to ${r.fixedVersion}` : " (no fix published — pin, override or compensate)"} — ${r.count} advisory(ies), worst ${r.worst}${r.kev ? ", KEV" : ""}`,
    );
  }
  const causes = ctx.narrative?.rootCauses ?? [];
  if (causes.length) {
    L.push(`Root causes (${AI_DISCLAIMER}) — fixing one closes every finding under it:`, "");
    for (const g of causes) L.push(`- **${g.cause}** (${g.findingIds.map((id) => `\`${id}\``).join(", ")}) — ${g.note.replace(/\n+/g, " ")}`);
    L.push("");
  }
  if (!PRIORITIES.some((p) => items[p].length)) {
    L.push(`_Nothing to remediate in what was adjudicated._`, "");
    return L;
  }
  for (const p of PRIORITIES) {
    if (!items[p].length) continue;
    L.push(`### ${PRIORITY_TITLE[p]} (${items[p].length})`, "");
    const shown = ctx.full ? items[p] : items[p].slice(0, PLAN_CAP);
    L.push(...shown);
    if (shown.length < items[p].length) L.push(`- _…and ${items[p].length - shown.length} more — \`render --full\`_`);
    L.push("");
  }
  return L;
}

// ── Annexes ─────────────────────────────────────────────────────────────────

function annexDismissed(ctx: Ctx): string[] {
  const L = [`## ${SECTIONS[11]}`, ""];
  const ds = ctx.dismissed;
  if (!ds.length) {
    L.push(`_Nothing dismissed._`, "");
    return L;
  }
  if (ctx.full) {
    L.push(`All ${ds.length} dismissals, with the ground and the argument that was made:`, "");
    L.push(...tierTable(ds), "");
    return L;
  }
  L.push(
    `${ds.length} candidate(s) dismissed — summarised. Every one keeps its id, ground and argument in \`findings.json\`; \`render --full\` lists them all.`,
    "",
  );
  L.push(`| ground | count | meaning |`, `|---|---|---|`);
  for (const [g, n] of countBy(ds, groundOf)) L.push(`| **${g}** | ${n} | ${GROUND_GLOSS(g)} |`);
  L.push("");
  L.push(`| produced by | count |`, `|---|---|`);
  for (const [t, n] of countBy(ds, (f) => (f.sources?.length ? f.sources.join("+") : f.tool)).slice(0, 10)) L.push(`| ${t} | ${n} |`);
  L.push("");
  L.push(`By shape:`, "");
  L.push(...familySummary(ds, ctx, FAMILY_TOP));
  const high = ds.filter((f) => f.severity === "critical" || f.severity === "high").sort((a, b) => rankScore(b) - rankScore(a) || byStr(a.id, b.id));
  if (high.length) {
    L.push(`HIGH/CRITICAL dismissals${high.length > TOP_DISMISSED ? ` (top ${TOP_DISMISSED} of ${high.length})` : ""} — the ones worth disagreeing with:`, "");
    for (const f of high.slice(0, TOP_DISMISSED)) {
      const why = stageNotes(f.message);
      L.push(`- ${badgeOf(f.severity)} ${f.title} — ${pathLine(f)} \`${f.id}\` — **${groundOf(f)}**${why ? `: ${oneLine(why, 160)}` : ""}`);
    }
    L.push("");
  }
  return L;
}

function annexNeedsHuman(ctx: Ctx): string[] {
  const L = [`## ${SECTIONS[12]}`, ""];
  if (!ctx.needs.length) {
    L.push(`_Nothing awaits a human decision._`, "");
    return L;
  }
  const shown = ctx.full ? ctx.needs : ctx.needs.slice(0, NEEDS_HUMAN_CAP);
  for (const f of shown) {
    const why = stageNotes(f.message);
    L.push(`- ${badgeOf(f.severity)} ${f.title} — \`${ctx.areaOf(f)}\` — ${pathLine(f)} \`${f.id}\`${why ? ` — ${oneLine(why, 160)}` : ""}`);
  }
  if (shown.length < ctx.needs.length) L.push(`- _…and ${ctx.needs.length - shown.length} more — \`render --full\`_`);
  L.push("");
  return L;
}

function usageCell(u: { exposed: boolean; input: number; output: number; cost: number }): string {
  if (!u.exposed) return "not reported";
  return `${u.input.toLocaleString("en-US")} in / ${u.output.toLocaleString("en-US")} out${u.cost ? ` · $${u.cost.toFixed(2)}` : ""}`;
}

function annexEngines(d: Dossier, opts: AuditReportOptions): string[] {
  const m = d.manifest;
  const L = [`## ${SECTIONS[13]}`, ""];
  L.push(
    `- engine: ultrasec ${m.version} (schema ${m.schemaVersion}) · extraction ${m.extraction ? `${m.extraction.tier}${m.extraction.ast ? ", AST" : ", **regex fallback**"}` : "unknown"}`,
  );
  L.push(`- languages: ${m.languages.join(", ") || "—"}`);
  if (m.frameworks?.length) L.push(`- stack: ${capList([...new Set(m.frameworks.map((f) => `${f.title}${f.version ? ` ${f.version}` : ""}`))], 12)}`);
  const passes = Object.entries(m.passes ?? {})
    .filter(([, v]) => v)
    .map(([k]) => k);
  if (passes.length) L.push(`- opt-in passes run: ${passes.join(", ")}`);
  L.push("");
  const st = m.toolStatus ?? [];
  const ran = st.filter((s) => s.status !== "skipped");
  if (ran.length) {
    L.push(`| scanner | status | findings | note |`, `|---|---|---|---|`);
    for (const s of ran) L.push(`| ${s.name} | ${s.status} | ${s.findings ?? "—"} | ${cell(oneLine(s.degraded ?? s.note ?? "", 120))} |`);
    L.push("");
  }
  const skipped = st.filter((s) => s.status === "skipped");
  if (skipped.length) L.push(`Skipped (not installed or nothing to scan): ${skipped.map((s) => s.name).join(", ")}.`, "");
  if (!st.length) L.push(`External scanners: ${m.toolsRun.length ? m.toolsRun.join(", ") : "none — graph + taint only"}.`, "");
  const c = opts.council;
  if (c) {
    L.push(`### Council`, "");
    L.push(`Snapshot \`${c.commit.slice(0, 12)}\` · ${c.reviewers.length} reviewer run(s) · total ${usageCell(c.totals)}`, "");
    L.push(`| reviewer | phase | model | status | usage | time |`, `|---|---|---|---|---|---|`);
    for (const r of c.reviewers) {
      const ms = r.attempts.reduce((a, t) => a + t.durationMs, 0);
      L.push(`| ${r.name} | ${r.phase} | ${r.model} | ${r.status} | ${usageCell(r.usage)} | ${Math.round(ms / 60000)} min |`);
    }
    L.push("");
    const { accepted, rejected } = c.decisions;
    L.push(`Decisions: ${accepted.length} accepted into the dossier · ${rejected.length} rejected.`, "");
    const shownRej = opts.full ? rejected : rejected.slice(0, 20);
    for (const r of shownRej)
      L.push(`- ✗ ${r.title} (${r.sources.join(", ")}) — ${r.reason ? oneLine(r.reason, 160) : "no reason recorded"}${r.by ? ` · ${r.by}` : ""}`);
    if (shownRej.length < rejected.length) L.push(`- _…and ${rejected.length - shownRej.length} more — \`render --full\`_`);
    if (shownRej.length) L.push("");
  }
  if (opts.artifacts?.length) L.push(`Run directory: ${opts.artifacts.map((a) => `\`${a}\``).join(" · ")}.`, "");
  return L;
}

function annexRevalidation(ctx: Ctx): string[] {
  const L = [`## ${SECTIONS[14]}`, ""];
  L.push(`| outcome | finding | fixed in | note |`, `|---|---|---|---|`);
  for (const f of ctx.revalidated) {
    const note = /Revalidation \([^)]+\)(?::\s*(.*))?/.exec(f.message)?.[1] ?? "";
    L.push(`| ${revalidationOf(f)} | ${cell(f.title)} \`${f.id}\` | ${f.fixedIn ?? "—"} | ${cell(oneLine(note, 160))} |`);
  }
  L.push("");
  return L;
}
