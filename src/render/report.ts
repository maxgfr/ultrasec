import { locationsLine, type Dossier } from "../store.js";
import { BROCARD_SUMMARY, SEVERITIES, type Finding, type Narrative, type Remediation, type Severity } from "../types.js";
import { pathMermaid } from "./mermaid.js";
import { compareWithinStatus } from "../rank.js";
import { groupFamilies, collapsedCount, familyCount } from "../family.js";
import { stageNotes } from "../util.js";
import { executiveSummaryMd, positivePatternsMd, suggestedFixMd, attackChainsMd, rootCausesMd, hardeningNotesMd, remediationMap } from "../narrative.js";
import { buildCoverage, enumeratedKindsOf, renderCoverageMd } from "../coverage.js";

// The tiered Markdown report: SUMMARY (TL;DR) and REPORT — the complete audit,
// every finding grouped by status (incl. dismissed), with the reasoning trail.

const BADGE: Record<Severity, string> = {
  critical: "🟥 CRITICAL",
  high: "🟧 HIGH",
  medium: "🟨 MEDIUM",
  low: "🟩 LOW",
  info: "⬜ INFO",
};

/** The severity badge, or a dash. A bare `BADGE[f.severity]` on a malformed
 *  finding interpolated the literal string "undefined" into the report — the
 *  Markdown twin of the TypeError the HTML renderer threw on the same run. */
function badgeOf(s: Severity | undefined | null): string {
  return (s && BADGE[s]) || "—";
}

/** Risk / EPSS / KEV / verified annotations, when present. */
function riskTag(f: Finding): string {
  const parts: string[] = [];
  if (typeof f.risk === "number") parts.push(`risk ${f.risk}`);
  if (typeof f.epss === "number") parts.push(`EPSS ${(f.epss * 100).toFixed(1)}%`);
  if (f.kev) parts.push(`🚨 CISA KEV${f.kevDateAdded ? ` (${f.kevDateAdded})` : ""}`);
  if (f.verified) parts.push(`✅ verified secret`);
  return parts.join(" · ");
}

/** Deterministic blame/owner provenance, when present (opt-in `--blame`). */
function provTag(f: Finding): string {
  const p = f.provenance;
  if (!p) return "";
  const who = [p.author, p.date].filter(Boolean).join(" · ");
  return [who, p.commit ? `@${p.commit}` : "", p.owner ? `owner ${p.owner}` : ""].filter(Boolean).join(" · ");
}

/** "agreed by a, b" when multiple scanners corroborate; else "via <tool>". */
function sourcesTag(f: Finding): string {
  const s = f.sources && f.sources.length ? f.sources : f.tool !== "ultrasec" ? [f.tool] : [];
  if (s.length > 1) return `agreed by ${s.join(", ")}`;
  return f.tool !== "ultrasec" ? `via ${f.tool}` : "";
}

function pathLine(f: Finding): string {
  if (f.path?.length) return f.path.map((p) => `\`${p.file}:${p.line}\``).join(" → ");
  if (f.sink) return `\`${f.sink.file}:${f.sink.line}\``;
  return "—";
}

function header(d: Dossier): string {
  const c = d.manifest.counts.bySeverity;
  const kev = d.findings.filter((f) => f.kev).length;
  const ranked = d.findings.some((f) => typeof f.risk === "number");
  const lines = [
    `repo \`${d.manifest.repo}\` · ultrasec ${d.manifest.version}`,
    `findings: **${d.manifest.counts.findings}** — ${SEVERITIES.map((s) => `${BADGE[s]} ${c[s]}`).join(" · ")}${kev ? ` · 🚨 ${kev} in CISA KEV` : ""}`,
    `tools: ${d.manifest.toolsRun.join(", ") || "none (graph + taint only)"}`,
  ];
  // Tool status, compacted. Printing all 21 adapters verbatim put a 1.5 KB wall
  // of "skipped — not installed" at the top of a 1.6 KB summary, with the three
  // FAILED scanners — the ones that are a coverage hole — buried inside it.
  // What ran, what broke, and a count for the rest.
  const st = d.manifest.toolStatus;
  if (st?.length) {
    const ran = st.filter((s) => s.status === "ran" || s.status === "empty");
    const failed = st.filter((s) => s.status === "failed");
    const skipped = st.filter((s) => s.status === "skipped");
    const bits = [`${ran.length} ran`];
    if (failed.length) bits.push(`**${failed.length} FAILED** (${failed.map((s) => s.name).join(", ")}) — a coverage hole, not an empty result`);
    if (skipped.length) bits.push(`${skipped.length} skipped`);
    lines.push(`scanners: ${bits.join(" · ")}`);
  }
  if (ranked) lines.push(`_ranked by composite risk (severity ⊕ EPSS ⊕ KEV)_`);
  return lines.join("  \n");
}

function statusTag(f: Finding): string {
  const v = f.verdict ? ` · verdict ${f.verdict}` : "";
  // The named ground for a dismissal, so a reader can disagree with the
  // refutation instead of just noticing that one happened.
  const b = f.brocard ? ` · ground: **${f.brocard}** (${BROCARD_SUMMARY[f.brocard]})` : "";
  return `status **${f.status}**${v}${b} · confidence ${f.confidence}`;
}

/**
 * How many lines one tier of the SUMMARY may spend.
 *
 * A summary is a thing you read, and 319 confirmed findings printed one per line
 * is not one — the first real audit produced a 58 KB "summary" whose Confirmed
 * section opened with ninety lockfile CVEs. Families collapse first, so the cap
 * bites on genuinely distinct findings; when it does, the tail is counted rather
 * than dropped, and REPORT.md still carries every one.
 */
const SUMMARY_LINES = 25;

/** One tier of the summary: families as a single `×N` line, then singles, capped. */
function summaryTier(findings: readonly Finding[], bold: boolean): string[] {
  const grouped = groupFamilies(findings);
  const tail = (f: Finding) => {
    const rt = riskTag(f);
    return ` (${f.cwe ?? f.category})${rt ? ` · ${rt}` : ""}`;
  };
  const name = (f: Finding) => (bold ? `**${f.title}**` : f.title);

  const rows = [
    ...grouped.families.map((fam) => ({
      at: fam.lead,
      line: `- ${badgeOf(fam.lead.severity)} ${name(fam.lead)} ${familyCount(fam)} — under \`${fam.root}\`${tail(fam.lead)}`,
    })),
    ...grouped.singles.map((f) => ({ at: f, line: `- ${badgeOf(f.severity)} ${name(f)} — ${pathLine(f)}${tail(f)}` })),
  ].sort((a, b) => compareWithinStatus(a.at, b.at));

  const out = rows.slice(0, SUMMARY_LINES).map((r) => r.line);
  if (rows.length > SUMMARY_LINES) out.push(`- _…and ${rows.length - SUMMARY_LINES} more — see REPORT.md._`);
  return out;
}

export function renderSummary(d: Dossier, narrative?: Narrative): string {
  const confirmed = d.findings.filter((f) => f.status === "confirmed").sort(compareWithinStatus);
  const needs = d.findings.filter((f) => f.status === "needs-human").sort(compareWithinStatus);
  const L: string[] = [`# Security audit — summary`, "", header(d), "", ...executiveSummaryMd(narrative), ...positivePatternsMd(narrative)];
  if (!confirmed.length && !needs.length) {
    L.push(d.findings.length ? `No confirmed issues. ${d.findings.length} candidate(s) — see REPORT.md.` : `No findings.`);
    L.push("");
    L.push(...coverageCaveat(d));
    return L.join("\n") + "\n";
  }
  if (confirmed.length) {
    L.push(`## Confirmed (${confirmed.length})`);
    L.push(...summaryTier(confirmed, true));
    L.push("");
  }
  if (needs.length) {
    L.push(`## Needs human review (${needs.length})`);
    L.push(...summaryTier(needs, false));
    L.push("");
  }
  L.push(...coverageCaveat(d));
  return L.join("\n") + "\n";
}

/**
 * The one line a summary must never omit: what this audit did not look at.
 *
 * A short summary is indistinguishable from a thorough audit that found little.
 * The full matrix lives in REPORT.md; this is the pointer that stops the summary
 * being read as a clean bill of health, plus any scanner that died — three of
 * nine did on the run that prompted it, one of them the only IaC scanner.
 */
function coverageCaveat(d: Dossier): string[] {
  const rows = buildCoverage(d, enumeratedKindsOf(d.findings));
  const unexamined = rows.filter((r) => r.state === "unexamined");
  const failed = (d.manifest.toolStatus ?? []).filter((s) => s.status === "failed");
  if (!unexamined.length && !failed.length) return [];
  const L = [`## Coverage caveat`, ""];
  if (unexamined.length) L.push(`**${unexamined.length} of ${rows.length}** categories were NOT examined: ${unexamined.map((r) => r.title).join(" · ")}.`);
  if (failed.length) L.push(`**${failed.length} scanner(s) failed** (${failed.map((s) => s.name).join(", ")}) — a hole in the table, not an empty category.`);
  L.push("");
  L.push(`This is a gap in the audit, not a clean bill of health. Full matrix in REPORT.md.`);
  return L;
}

function renderFinding(f: Finding, opts: { mermaid?: boolean; remediation?: Remediation } = {}): string {
  const L: string[] = [];
  L.push(`### ${badgeOf(f.severity)} ${f.title}`);
  L.push("");
  const src = sourcesTag(f);
  L.push(
    // `vulnClass` first when the author named one: "stored-xss" is what they
    // determined, "taint" is only where it had to be stored.
    `\`${f.id}\` · ${f.cwe ? `[${f.cwe}](${(f.references ?? [])[0] ?? `https://cwe.mitre.org/`}) · ` : ""}${f.vulnClass ? `**${f.vulnClass}** (${f.category})` : f.category} · ${statusTag(f)}${src ? ` · ${src}` : ""}`,
  );
  const rt = riskTag(f);
  if (rt) {
    L.push("");
    L.push(`**Risk:** ${rt}`);
  }
  L.push("");
  L.push(`**Path:** ${pathLine(f)}`);
  if (f.locations?.length) {
    L.push("");
    L.push(`**Affects:** ${locationsLine(f.locations)}`);
  }
  const pv = provTag(f);
  if (pv) {
    L.push("");
    L.push(`**Provenance:** ${pv}`);
  }
  L.push("");
  L.push(f.message);
  if (f.exploitPath) {
    L.push("");
    L.push(`**Exploit path:** ${f.exploitPath}`);
  }
  // AI-authored suggested fix (presence-gated): only when a remediation for this
  // finding was provided via --narrative; absent ⇒ no change to today's output.
  L.push(...suggestedFixMd(opts.remediation));
  if (opts.mermaid) {
    const mm = pathMermaid(f);
    if (mm) {
      L.push("");
      L.push("```mermaid");
      L.push(mm);
      L.push("```");
    }
  }
  if (f.references?.length) {
    L.push("");
    L.push(
      `References: ${f.references
        .slice(0, 5)
        .map((r) => `<${r}>`)
        .join(" · ")}`,
    );
  }
  return L.join("\n");
}

/**
 * A tier as a compact table — severity, finding, where, and WHY.
 *
 * Compact must not mean lossy, and the line between them is: everything that is
 * a JUDGMENT stays, everything mechanical goes. So the auditor's argument stays
 * and the engine's boilerplate, the mermaid diagram and the reference URLs do
 * not — those are derivable from `findings.json`, and the argument is not.
 *
 * Dropping the argument was a real defect in the first cut of this: the refuted
 * tier of one audit carried **384 distinct refutation arguments** across 1041
 * findings, and a table showing only the named ground hid every one. "An audit
 * trail that hides its refutations cannot be checked" is the reason the tier is
 * printed at all; printing it without the reasoning honours the letter of that
 * and none of it.
 *
 * `locations[]` likewise takes precedence over the single cited path: a
 * dependency advisory merged across versions cites one lockfile line but AFFECTS
 * several, and dropping that would make a two-workspace monorepo look like a
 * one-workspace problem.
 */
function tierTable(findings: readonly Finding[]): string[] {
  const L = [`| | finding | where | why |`, `|---|---|---|---|`];
  for (const f of findings) {
    const ground = f.brocard ? `**${f.brocard}**` : (f.verdict ?? "");
    const note = stageNotes(f.message).replace(/\|/g, "\\|").replace(/\n+/g, " ");
    const why = [ground, note].filter(Boolean).join(" — ") || "—";
    const where = f.locations?.length ? locationsLine(f.locations) : pathLine(f);
    L.push(`| ${badgeOf(f.severity)} | ${f.title} <code>${f.id}</code> | ${where} | ${why} |`);
  }
  return L;
}

/**
 * A tier as full write-ups, with repeated findings collapsed to one.
 *
 * The old renderer emitted a section per finding, mermaid diagram included, for
 * every tier — which on a real audit meant 1041 refuted candidates rendered in
 * full and a 1.5 MB file. A family now writes its exemplar once and lists the
 * other locations in a table under it.
 */
function tierSections(findings: readonly Finding[], rem: Map<string, Remediation>, mermaid: boolean): string[] {
  const grouped = groupFamilies(findings);
  const blocks = [
    ...grouped.families.map((fam) => ({
      at: fam.lead,
      body: [
        renderFinding(fam.lead, { mermaid, remediation: rem.get(fam.lead.id) }),
        "",
        // Every member shares this finding's title, its path root AND its
        // adjudication — that is what makes them one judgment and what the key
        // enforces. So the write-up above speaks for all of them, and the table
        // only has to say where each one is.
        `**${fam.members.length} occurrence(s)**, same location root \`${fam.root}\`, same adjudication:`,
        "",
        `| id | location | severity |`,
        `|---|---|---|`,
        ...fam.members.map((m) => `| \`${m.id}\` | ${pathLine(m)} | ${m.severity ?? "—"} |`),
      ].join("\n"),
    })),
    ...grouped.singles.map((f) => ({ at: f, body: renderFinding(f, { mermaid, remediation: rem.get(f.id) }) })),
  ].sort((a, b) => compareWithinStatus(a.at, b.at));

  const L: string[] = [];
  for (const b of blocks) {
    L.push(b.body);
    L.push("");
  }
  const folded = collapsedCount(grouped);
  if (folded) L.push(`_${folded} repeated occurrence(s) folded into the write-ups above; every one is in \`findings.json\`._`, "");
  return L;
}

export function renderReport(d: Dossier, narrative?: Narrative): string {
  const rem = remediationMap(narrative);
  const L: string[] = [`# Security audit — report`, "", header(d), "", ...executiveSummaryMd(narrative), ...positivePatternsMd(narrative)];
  const byStatus = (s: Finding["status"]) => d.findings.filter((f) => f.status === s).sort(compareWithinStatus);
  const confirmed = byStatus("confirmed");
  const needs = byStatus("needs-human");
  const open = byStatus("open");
  const dismissed = byStatus("dismissed");

  if (!confirmed.length && !needs.length && !open.length && !dismissed.length) {
    L.push(`No findings.`);
    return L.join("\n") + "\n";
  }

  // Full write-ups for what someone must act on…
  if (confirmed.length) {
    L.push(`## Confirmed (${confirmed.length})`, "");
    L.push(...tierSections(confirmed, rem, true));
  }
  if (needs.length) {
    L.push(`## Needs human review (${needs.length})`, "");
    L.push(...tierSections(needs, rem, true));
  }
  // …and tables for what is still a question or already answered. Both tiers
  // stay in the report — an audit trail that omits its refutations cannot be
  // checked — but neither earns a page of prose and a diagram per row.
  if (open.length) {
    L.push(`## Unadjudicated candidates (${open.length})`, "");
    L.push(`Enumerated, not yet decided. Recall-oriented by design: many are false positives.`, "");
    L.push(...tierTable(open), "");
  }
  if (dismissed.length) {
    L.push(`## Refuted (${dismissed.length})`, "");
    L.push(`Kept so the refutations can be disagreed with: **why** carries the named ground and the`, `argument that was actually made.`, "");
    L.push(...tierTable(dismissed), "");
  }
  // What the compact tiers drop, said out loud. A reader who cannot tell
  // "summarized" from "omitted" has to distrust the whole document.
  if (open.length || dismissed.length) {
    L.push(
      `_The compact tiers above carry every finding's id, location, severity and adjudication —` +
        ` what is dropped is the engine's own boilerplate, the diagrams and the CWE links, all of` +
        ` which are in \`findings.json\`._`,
      "",
    );
  }
  L.push(...attackChainsMd(narrative), ...rootCausesMd(narrative), ...hardeningNotesMd(narrative));
  // What the audit did NOT look at, stated in the report itself. Without it a
  // short report is indistinguishable from a thorough one that found little.
  // Share `enumeratedKindsOf` with the `coverage` command rather than
  // re-deriving the kind set here. The hand-rolled version this replaces dropped
  // `f.cwe`, so REPORT.md and `ultrasec coverage` disagreed on every CWE-keyed
  // pack (Top 10, CWE Top 25) — which the comment on that helper promises can
  // never happen.
  L.push(renderCoverageMd(buildCoverage(d, enumeratedKindsOf(d.findings)), undefined, d));
  L.push(`---`);
  L.push(`Engine: ultrasec ${d.manifest.version}. ${d.manifest.generatedNote}`);
  return L.join("\n") + "\n";
}
