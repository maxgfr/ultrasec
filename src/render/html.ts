import { toolStatusLines, type Dossier } from "../store.js";
import { SEVERITIES, type Finding, type Narrative, type Remediation, type Severity } from "../types.js";
import { compareWithinStatus } from "../rank.js";
import { groupFamilies, collapsedCount, type Family } from "../family.js";
import { buildCoverage, enumeratedKindsOf, type CoverageRow } from "../coverage.js";
import { AI_DISCLAIMER, hasNarrativeContent, remediationMap } from "../narrative.js";
import { groupAdvisoriesByPackage } from "../deps.js";
import { bySurface, SURFACE_TITLE, unadjudicatedCode, type Surface } from "../surface.js";
import { stageNotes } from "../util.js";

// A single self-contained index.html — embedded CSS, no external assets, no JS
// required. The cross-file path renders as offline boxes-and-arrows so it works
// without a network (Mermaid source still lives in the Markdown report).
//
// ── Why this is a document and not a dump ──────────────────────────────────
//
// It used to print every non-dismissed finding in full, in one flat column, in
// risk order. On the audit that prompted the rewrite that produced a **2.1 MB**
// page: no navigation, no grouping, 604 near-identical entries, and the three
// confirmed criticals below hundreds of refuted candidates. Every fact was in
// there and none of it was findable, which for a report is the same as being
// wrong.
//
// So: a fixed registry rail to navigate by, severity tiles to size the problem,
// the confirmed findings first as readable cards, repeated families collapsed to
// one card with a count, and the refuted tier as a compact table under a fold —
// present, because an audit trail that hides its refutations cannot be checked,
// but not in the way of the findings.

// A report is the one artifact that must survive a malformed finding.
//
// `render` used to throw `TypeError: Cannot read properties of null (reading
// 'toUpperCase')` on a finding whose `severity` was null, and an auditor with a
// finished, adjudicated run could not produce a report at all until the rows
// were hand-patched. The validators upstream now make that finding
// unconstructible; these fallbacks mean that if one ever appears again it costs
// a dash in one cell, not the document.
const MISSING = "—";

function esc(s: string | undefined | null): string {
  if (s === undefined || s === null) return MISSING;
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

/**
 * A reference is a URL a scanner or an adjudicator wrote into the dossier, and
 * the report is opened in a browser. Only `http:`/`https:` may become a link —
 * `javascript:` and `data:` would execute or render attacker-chosen content
 * from inside a trusted-looking report. Anything else is shown as text.
 */
function safeHref(ref: string): string | undefined {
  try {
    const u = new URL(ref);
    if (u.protocol !== "http:" && u.protocol !== "https:") return undefined;
    return ref; // the original text, not `u.href` — no silent normalization of what the dossier says
  } catch {
    return undefined;
  }
}

/** Shorthand severity class: `c`/`h`/`m`/`l`/`i`, or `x` for a malformed one. */
function sevClass(s: Severity | undefined | null): string {
  return s ? s[0]!.toLowerCase() : "x";
}

function sevLabel(s: Severity | undefined | null): string {
  return s ? String(s).toUpperCase() : MISSING;
}

function pathHtml(f: Finding): string {
  if (!f.path?.length) return f.sink ? `<p class="anchor"><code>${esc(f.sink.file)}:${f.sink.line}</code></p>` : "";
  const nodes = f.path
    .map((p, i) => {
      const tag = i === 0 ? "source" : i === f.path!.length - 1 ? "sink" : "hop";
      const sym = p.symbol ? `<div class="sym">${esc(p.symbol)}()</div>` : "";
      return `<div class="node ${tag}"><div class="loc">${esc(p.file)}:${p.line}</div>${sym}<div class="why">${esc(p.why)}</div></div>`;
    })
    .join('<div class="arrow">→</div>');
  return `<div class="flow">${nodes}</div>`;
}

/** Risk / EPSS / KEV / reachability chips — the ranking, made legible. */
function chipsHtml(f: Finding): string {
  const out: string[] = [];
  if (typeof f.risk === "number") out.push(`<span class="chip risk">risk ${f.risk}</span>`);
  if (typeof f.epss === "number") out.push(`<span class="chip">EPSS ${(f.epss * 100).toFixed(1)}%</span>`);
  if (f.kev) out.push(`<span class="chip kev">CISA KEV${f.kevDateAdded ? ` ${esc(f.kevDateAdded)}` : ""}</span>`);
  if (f.verified) out.push(`<span class="chip kev">verified secret</span>`);
  // The axis severity alone cannot express: is anything putting this on a path
  // that runs? `runtime` is the unremarkable case and stays unlabelled.
  if (f.reachability && f.reachability !== "runtime") out.push(`<span class="chip reach">${esc(f.reachability)}</span>`);
  if (f.noise) out.push(`<span class="chip">de-prioritized: ${esc(f.noise)}</span>`);
  return out.length ? `<div class="chips">${out.join("")}</div>` : "";
}

function sourcesHtml(f: Finding): string {
  const s = f.sources && f.sources.length ? f.sources : f.tool !== "ultrasec" ? [f.tool] : [];
  if (s.length > 1) return ` · agreed by ${esc(s.join(", "))}`;
  return f.tool !== "ultrasec" ? ` · via ${esc(f.tool)}` : "";
}

function fixHtml(r?: Remediation): string {
  if (!r) return "";
  const patch = r.patch ? `<pre class="ai-patch"><code>${esc(r.patch)}</code></pre>` : "";
  return `<div class="ai-fix"><strong>Suggested fix (AI):</strong> ${esc(r.fix)}${r.owner ? ` · owner ${esc(r.owner)}` : ""}${patch}</div>`;
}

/**
 * The attacker scenario, when the audit produced one.
 *
 * `exploitPath` is what `verify` demands before a finding may be called
 * `supported` — who, what they send, what they get. Giving it its own block
 * rather than a run-on paragraph is the difference between a report a developer
 * acts on and one they skim.
 */
function scenarioHtml(f: Finding): string {
  if (!f.exploitPath) return "";
  return `<div class="scenario"><div class="s-label">Attack scenario</div><p>${esc(f.exploitPath)}</p></div>`;
}

function refsHtml(f: Finding): string {
  const refs = (f.references ?? [])
    .slice(0, 5)
    .map((r) => {
      const label = esc(String(r).replace(/^https?:\/\//, ""));
      const href = safeHref(String(r));
      return href ? `<a href="${esc(href)}" rel="noreferrer noopener">${label}</a>` : `<span class="ref-text">${label}</span>`;
    })
    .join(" · ");
  return refs ? `<p class="refs">${refs}</p>` : "";
}

function metaHtml(f: Finding): string {
  return `<div class="meta"><code>${esc(f.id)}</code>${f.cwe ? ` · ${esc(f.cwe)}` : ""} · ${esc(f.vulnClass ?? f.category)} · ${esc(f.status ?? MISSING)}${
    f.verdict ? ` · ${esc(f.verdict)}` : ""
  } · confidence ${esc(f.confidence)}${sourcesHtml(f)}</div>`;
}

function findingHtml(f: Finding, rem?: Remediation, extra = ""): string {
  return `
      <article class="find ${sevClass(f.severity)}" id="${esc(f.id)}">
        <div class="find-top"><span class="pill">${esc(sevLabel(f.severity))}</span><h3>${esc(f.title)}</h3></div>
        ${metaHtml(f)}
        ${chipsHtml(f)}
        ${pathHtml(f)}
        <p class="msg">${esc(f.message)}</p>
        ${scenarioHtml(f)}
        ${fixHtml(rem)}
        ${extra}
        ${refsHtml(f)}
      </article>`;
}

/**
 * Where a finding is, for the compact tables.
 *
 * `locations[]` takes precedence over the single cited anchor, and dropping it
 * was a real asymmetry: the Markdown report has printed the merged instances
 * since `locationsLine` landed, while the HTML showed only the representative.
 * A CVE the correlator merged across three lockfiles rendered as one line, so a
 * two-workspace monorepo looked like a one-workspace problem in one artifact
 * and not the other. Capped at three, because a `pnpm-lock.yaml` advisory can
 * carry a dozen and the cell is not the place to enumerate them.
 */
const AT_LOCATIONS = 3;

function atOf(f: Finding): string {
  if (f.locations?.length) {
    const shown = f.locations.slice(0, AT_LOCATIONS).map((e) => `${e.version ? `v${e.version} ` : ""}${e.file}${e.line !== undefined ? `:${e.line}` : ""}`);
    const rest = f.locations.length - shown.length;
    return shown.join(" · ") + (rest > 0 ? ` +${rest} more` : "");
  }
  const loc = f.sink ?? f.source ?? f.path?.[f.path.length - 1];
  return loc ? `${loc.file}:${loc.line}` : MISSING;
}

/**
 * A repeated finding, rendered once with its other locations folded away.
 *
 * The members are listed, not merged: `findings.json` still holds each one, and
 * a reader who wants the 149th `pickle` warning can open the fold and get its
 * id. What the fold removes is 148 restatements of the same paragraph — and
 * they ARE the same paragraph, because the family key includes the adjudication.
 * Two findings refuted for different reasons are never one card.
 */
function familyHtml(fam: Family, rem?: Remediation): string {
  const rows = fam.members
    .map((m) => `<tr><td><code>${esc(m.id)}</code></td><td class="at">${esc(atOf(m))}</td><td>${esc(sevLabel(m.severity))}</td></tr>`)
    .join("");
  const extra = `<details class="members"><summary>${fam.members.length} occurrence(s), same root <code>${esc(fam.root)}</code>, same adjudication</summary>
          <div class="tw"><table><thead><tr><th>id</th><th>location</th><th>severity</th></tr></thead><tbody>${rows}</tbody></table></div>
        </details>`;
  return findingHtml(fam.lead, rem, extra);
}

/**
 * A whole tier as one scannable table — for the refuted and unadjudicated.
 *
 * Carries the auditor's ARGUMENT, not just the named ground. Compact must not
 * mean lossy: one audit's refuted tier held 384 distinct refutation arguments
 * across 1041 findings, and a table showing only the brocard hid every one of
 * them — while the section header claimed the tier was printed so the
 * refutations could be checked.
 */
function tableRowHtml(f: Finding, count = 1, members: readonly Finding[] = []): string {
  const ground = f.brocard ? `<strong>${esc(f.brocard)}</strong>` : f.verdict ? esc(f.verdict) : "";
  const note = stageNotes(f.message);
  const why = [ground, note ? esc(note) : ""].filter(Boolean).join(" — ") || MISSING;
  const tally = count > 1 ? ` <span class="chip">&times;${count}</span>` : "";
  const where =
    count > 1
      ? `<details class="members"><summary>${count} location(s) under <code>${esc(atOf(f))}</code></summary><ul>${members
          .map((m) => `<li>${esc(atOf(m))} <code>${esc(m.id)}</code></li>`)
          .join("")}</ul></details>`
      : esc(atOf(f));
  return `<tr><td><span class="dot ${sevClass(f.severity)}"></span>${esc(sevLabel(f.severity))}</td><td>${esc(f.title)}${tally} <code>${esc(
    f.id,
  )}</code></td><td class="at">${where}</td><td class="prose">${why}</td></tr>`;
}

function tableHtml(findings: readonly Finding[]): string {
  // Families collapse here too. The card tiers have folded repetitions since
  // `family.ts` landed and the tables never did, which is why one audit's
  // unadjudicated tier was 882 rows: 60 of them were the same SQL-injection
  // shape under `targets/`, each restating the same sentence. The fold is
  // presentation only — every member keeps its id, listed under the summary.
  const grouped = groupFamilies(findings);
  const rows = [
    ...grouped.families.map((fam) => ({ at: fam.lead, html: tableRowHtml(fam.lead, fam.members.length, fam.members) })),
    ...grouped.singles.map((f) => ({ at: f, html: tableRowHtml(f) })),
  ].sort((a, b) => compareWithinStatus(a.at, b.at));
  return `<div class="tw"><table><thead><tr><th>severity</th><th>finding</th><th>location</th><th>why</th></tr></thead><tbody>${rows
    .map((r) => r.html)
    .join("")}</tbody></table></div>`;
}

/** One tier of findings: cards for the singles, one card per collapsed family. */
function tierHtml(findings: readonly Finding[], rem: Map<string, Remediation>): string {
  const grouped = groupFamilies(findings);
  const cards = [
    ...grouped.families.map((fam) => ({ at: fam.lead, html: familyHtml(fam, rem.get(fam.lead.id)) })),
    ...grouped.singles.map((f) => ({ at: f, html: findingHtml(f, rem.get(f.id)) })),
  ].sort((a, b) => compareWithinStatus(a.at, b.at));
  const folded = collapsedCount(grouped);
  const note = folded ? `<p class="fold-note">${folded} repeated occurrence(s) folded into the cards above — open a card's fold for every location.</p>` : "";
  return cards.map((c) => c.html).join("\n") + note;
}

// ── The state of the audit, said before anything else ──────────────────────

/**
 * The banner a run gets when nobody read the code.
 *
 * The audit that prompted this rendered 882 candidates, 0 adjudicated, with an
 * empty `why` column on every row — and said nothing about it. `SUMMARY.md`
 * opened with "No confirmed issues", which is true and reads as a clean bill of
 * health. It was a scan, not an audit, and the document that came out of it was
 * indistinguishable from one.
 *
 * Dependency advisories left `open` do NOT trigger this: working the CVE list
 * in risk order and stopping at the bar is the prescribed outcome
 * (references/supply-chain.md). An unread cross-file flow is a different thing
 * — deciding it means opening the file, and no one did.
 */
function bannerHtml(unread: readonly Finding[]): string {
  if (!unread.length) return "";
  const crit = unread.filter((f) => f.severity === "critical").length;
  const high = unread.length - crit;
  const tally = [crit ? `${crit} CRITICAL` : "", high ? `${high} HIGH` : ""].filter(Boolean).join(" and ");
  return `
  <section id="incomplete"><div class="banner">
    <h2>Incomplete audit &mdash; ${unread.length} source-code candidate(s) were never read</h2>
    <p class="prose">${esc(tally)} candidate(s) in this repository's own code still have no verdict. Nobody opened the files and followed the flows, so
      this document is engine output, not an audit: absence of confirmed findings below means <em>undecided</em>, not <em>safe</em>.</p>
    <p class="prose">Dependency advisories are worked as a ranked list and may legitimately stay open. Source-code candidates are read one at a time.</p>
    <p class="next">ultrasec paths --run &lt;run&gt; --surface code &nbsp;&rarr;&nbsp; ultrasec dossier &lt;id&gt; --run &lt;run&gt; &nbsp;&rarr;&nbsp; ultrasec verify --apply verdicts.json --run &lt;run&gt;</p>
  </div></section>`;
}

// ── The summary band, split by surface ─────────────────────────────────────

/** A severity histogram as one proportional bar. */
function barHtml(fs: readonly Finding[]): string {
  if (!fs.length) return "";
  const seg = SEVERITIES.map((sev) => ({ k: SEV_KEY[sev], n: fs.filter((f) => f.severity === sev).length }))
    .filter((x) => x.n > 0)
    .map((x) => `<span class="${x.k}" style="width:${((x.n / fs.length) * 100).toFixed(2)}%"></span>`)
    .join("");
  return `<div class="sf-bar">${seg}</div>`;
}

/** "0 confirmed - 3 needs human - 620 open - 0 refuted", omitting the zeroes. */
function statusLine(fs: readonly Finding[]): string {
  const n = (st: Finding["status"]) => fs.filter((f) => f.status === st).length;
  const bits = [
    n("confirmed") ? `${n("confirmed")} confirmed` : "",
    n("needs-human") ? `${n("needs-human")} needs human` : "",
    n("open") ? `${n("open")} undecided` : "",
    n("dismissed") ? `${n("dismissed")} refuted` : "",
  ].filter(Boolean);
  return bits.join(" \u00b7 ") || "none";
}

/**
 * Three cards instead of five severity tiles.
 *
 * The old band answered "how bad", which a reader cannot act on until they know
 * "bad where". Splitting the counts by surface makes the first screen say the
 * thing the flat table hid: this repo has N problems of its own, and M
 * advisories about code it merely installs.
 */
function surfacesHtml(groups: Record<Surface, Finding[]>): string {
  const card = (sf: Surface, lead: boolean, sub: string) => {
    const fs = groups[sf];
    return `<div class="sf${lead ? " lead" : ""}"><div class="sf-h"><span class="t">${esc(SURFACE_TITLE[sf])}</span><span class="n">${fs.length}</span></div>
      ${barHtml(fs)}<div class="sf-sub">${esc(statusLine(fs))}</div><div class="sf-sub">${esc(sub)}</div></div>`;
  };
  return `<div class="surfaces">
    ${card("code", true, "cross-file flows, missing guards, unsafe sinks - read one at a time")}
    ${card("supply", false, "committed secrets, CI and IaC configuration - your repository")}
    ${card("deps", false, "advisories on installed packages - triaged as a ranked list")}
  </div>`;
}

// ── Attack surface: where an attacker gets in ──────────────────────────────

/** The vulnerability class of a flow, preferring the auditor's name for it. */
function classOf(f: Finding): string {
  return f.vulnClass ?? f.sink?.kind ?? f.cwe ?? f.category;
}

/**
 * One row per entry point, so the code section opens with the attacker's view.
 *
 * A list of 620 findings does not tell you that eleven of them enter through
 * one Next.js API route. Grouping by `path[0].file` does, and it costs nothing
 * to compute: it is the first hop of the chain the engine already enumerated.
 * Only flows with a real path appear here — a standalone SAST hit has a
 * location but no entry point, and inventing one for it would be a claim the
 * engine never made.
 */
function entryPointsHtml(code: readonly Finding[]): string {
  const flows = code.filter((f) => f.path && f.path.length > 0);
  if (!flows.length) return "";
  const byEntry = new Map<string, Finding[]>();
  for (const f of flows) {
    const at = f.path![0]!.file;
    const list = byEntry.get(at);
    if (list) list.push(f);
    else byEntry.set(at, [f]);
  }
  const rows = [...byEntry.entries()]
    .map(([file, fs]) => ({ file, fs, top: fs.slice().sort(compareWithinStatus)[0]! }))
    .sort((a, b) => compareWithinStatus(a.top, b.top) || b.fs.length - a.fs.length)
    .map(({ file, fs, top }) => {
      const classes = [...new Set(fs.map(classOf))].sort();
      return `<tr><td><span class="dot ${sevClass(top.severity)}"></span>${esc(sevLabel(top.severity))}</td><td class="at">${esc(file)}</td><td class="num">${
        fs.length
      }</td><td>${classes.map((c) => `<span class="chip">${esc(c)}</span>`).join(" ")}</td></tr>`;
    })
    .join("");
  return `<details open><summary>Attack surface &mdash; ${byEntry.size} entry point(s) reaching a dangerous sink</summary>
    <div class="tw"><table><thead><tr><th>worst</th><th>entry point</th><th>flows</th><th>classes</th></tr></thead><tbody>${rows}</tbody></table></div>
  </details>`;
}

// ── Dependencies, rolled up per package ────────────────────────────────────

function depsHtml(deps: readonly Finding[]): string {
  if (!deps.length) return "";
  const rows = groupAdvisoriesByPackage(deps)
    .map((r) => {
      const versions = r.versions.length ? r.versions.slice(0, 3).join(", ") + (r.versions.length > 3 ? ` +${r.versions.length - 3}` : "") : MISSING;
      const sig = [
        r.kev ? `<span class="kev">CISA KEV${r.kev > 1 ? ` \u00d7${r.kev}` : ""}</span>` : "",
        typeof r.maxEpss === "number" ? `EPSS ${(r.maxEpss * 100).toFixed(1)}%` : "",
        r.reachability === "toolchain" ? `<span class="tc">dev/toolchain</span>` : "",
      ]
        .filter(Boolean)
        .join(" \u00b7 ");
      const advisories = `<details class="members"><summary>${r.count} advisor${r.count === 1 ? "y" : "ies"}</summary><ul>${r.advisories
        .map((a) => `<li>${esc(sevLabel(a.severity))} &mdash; ${esc(a.title)} <code>${esc(a.cve ?? a.id)}</code></li>`)
        .join("")}</ul></details>`;
      // Folded, never truncated. An advisory the correlator merged across three
      // lockfiles must not render as a one-workspace problem — that asymmetry
      // between the Markdown report and the HTML is the defect `atOf` had.
      const locLabel = (l: { file: string; line?: number; version?: string }) =>
        `${l.version ? `v${l.version} ` : ""}${l.file}${l.line !== undefined ? `:${l.line}` : ""}`;
      const where = !r.locations.length
        ? MISSING
        : r.locations.length <= 2
          ? esc(r.locations.map(locLabel).join(" · "))
          : `<details class="members"><summary>${r.locations.length} location(s)</summary><ul>${r.locations
              .map((l) => `<li>${esc(locLabel(l))}</li>`)
              .join("")}</ul></details>`;
      return `<tr><td><span class="dot ${sevClass(r.worst)}"></span>${esc(sevLabel(r.worst))}</td><td class="pkg">${esc(r.pkg)}</td><td class="num">${esc(
        versions,
      )}</td><td>${advisories}</td><td class="num">${r.fixedVersion ? esc(r.fixedVersion) : "<em>no fix published</em>"}</td><td class="sig">${
        sig || MISSING
      }</td><td class="at">${where}</td></tr>`;
    })
    .join("");
  return `<div class="tw"><table><thead><tr><th>worst</th><th>package</th><th>installed</th><th>advisories</th><th>upgrade to</th><th>signals</th><th>where</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

// ── AI-authored narrative sections (presence-gated) ─────────────────────────

function aiSectionHtml(title: string, items: string): string {
  return `\n  <section class="ai-narrative"><h2>${esc(title)} <span class="ai-tag">AI</span></h2><p class="ai-note">${esc(AI_DISCLAIMER)}</p>${items}</section>`;
}

function execSummaryHtml(n?: Narrative): string {
  return n?.executiveSummary ? aiSectionHtml("Executive summary", `<p>${esc(n.executiveSummary)}</p>`) : "";
}

function positivePatternsHtml(n?: Narrative): string {
  return n?.positivePatterns ? aiSectionHtml("What the codebase does well", `<p>${esc(n.positivePatterns)}</p>`) : "";
}

function hardeningNotesHtml(n?: Narrative): string {
  if (!n?.hardeningNotes?.length) return "";
  const items = `<p class="ai-note">Defense-in-depth suggestions — not findings; excluded from the severity counts.</p><ul>${n.hardeningNotes
    .map((h) => `<li>${esc(h)}</li>`)
    .join("")}</ul>`;
  return aiSectionHtml("Hardening notes", items);
}

/**
 * The attack chains, as the callout they deserve.
 *
 * A chain is the one thing in the whole report that no single finding states:
 * three defects that are each survivable and together are not. It goes at the
 * top, styled as the alarm it is, rather than in a list below four hundred
 * candidates.
 */
function chainsHtml(n?: Narrative): string {
  if (!n?.attackChains?.length) return "";
  const items = n.attackChains
    .map(
      (c) =>
        `<div class="chain"><h3>${esc(c.title)}</h3><div class="meta">${c.findingIds
          .map((id) => `<a href="#${esc(id)}"><code>${esc(id)}</code></a>`)
          .join(" → ")}</div><p>${esc(c.narrative)}</p></div>`,
    )
    .join("");
  return `\n  <section id="chains"><h2>Attack chains <span class="ai-tag">AI</span></h2><p class="ai-note">${esc(AI_DISCLAIMER)}</p>${items}</section>`;
}

function rootCausesHtml(n?: Narrative): string {
  if (!n?.rootCauses?.length) return "";
  const items = n.rootCauses
    .map(
      (g) =>
        `<div class="ai-block"><h3>${esc(g.cause)}</h3><div class="meta">${g.findingIds
          .map((id) => `<a href="#${esc(id)}"><code>${esc(id)}</code></a>`)
          .join(", ")}</div><p>${esc(g.note)}</p></div>`,
    )
    .join("");
  return aiSectionHtml("Root-cause groups", items);
}

// ── Coverage: what the audit did NOT look at ───────────────────────────────

const COVERAGE_MARK: Record<CoverageRow["state"], string> = {
  examined: "examined",
  engine: "enumerated",
  unexamined: "NOT examined",
};

/**
 * The coverage table and the scanners that died.
 *
 * A short report is indistinguishable from a thorough one that found little
 * unless it says what it did not look at. This is the section the audit that
 * prompted the rewrite got right and the HTML never showed: three of nine
 * scanners failed, one of them the only IaC scanner, and the page said nothing.
 */
function coverageHtml(d: Dossier): string {
  const rows = buildCoverage(d, enumeratedKindsOf(d.findings));
  const failed = (d.manifest.toolStatus ?? []).filter((s) => s.status === "failed");
  const body = rows
    .map(
      (r) =>
        `<tr class="${r.state}"><td class="at">${esc(r.id)}</td><td>${esc(r.title)}</td><td>${esc(COVERAGE_MARK[r.state])}</td><td>${r.hits || MISSING}</td></tr>`,
    )
    .join("");
  const failedBlock = failed.length
    ? `<div class="warn"><strong>${failed.length} scanner(s) failed</strong> — each is a hole in the table above, not a category with nothing in it.
       <ul>${failed.map((s) => `<li><code>${esc(s.name)}</code> — ${esc(s.note ?? "run failed")}</li>`).join("")}</ul></div>`
    : "";
  return `
  <section id="coverage">
    <h2>Coverage — what was not looked at</h2>
    <p>A category marked <strong>NOT examined</strong> is a gap in this audit, not a clean bill of health.</p>
    ${failedBlock}
    <div class="tw"><table><thead><tr><th>#</th><th>category</th><th>state</th><th>findings</th></tr></thead><tbody>${body}</tbody></table></div>
  </section>`;
}

// ── The registry rail ──────────────────────────────────────────────────────

function railHtml(sections: readonly { id: string; label: string }[], actionable: readonly Finding[]): string {
  if (!sections.length && !actionable.length) return "";
  const nav = sections.map((x) => `<li><a href="#${esc(x.id)}"><span class="rt">${esc(x.label)}</span></a></li>`).join("");
  const items = actionable
    .map((f) => `<li><a href="#${esc(f.id)}"><span class="dot ${sevClass(f.severity)}"></span><span class="rt">${esc(f.title)}</span></a></li>`)
    .join("");
  // Section anchors first, so the rail exists even on a run with nothing
  // confirmed. It used to list only the actionable findings, which meant the
  // page with the most to navigate — hundreds of undecided candidates — was the
  // one page with no navigation at all.
  const registry = items ? `<div class="rail-title">Registry</div><ol>${items}</ol>` : "";
  return `<nav class="rail" aria-label="Report navigation"><div class="rail-title">Sections</div><ol>${nav}</ol>${registry}</nav>`;
}

const CSS = `
  :root {
    color-scheme: light dark;
    --ground:#f6f7f9; --surface:#fff; --surface-alt:#eef1f5;
    --ink:#14181f; --ink-soft:#4e5769; --ink-faint:#79808f;
    --rule:#dce1ea; --rule-soft:#e9edf3; --accent:#24487a;
    --crit:#9b2233; --high:#b05315; --med:#7e6212; --low:#3f6350; --info:#5a6472; --unknown:#79808f;
    --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --ground:#101319; --surface:#171b23; --surface-alt:#1e232d;
      --ink:#e6eaf2; --ink-soft:#a3acbe; --ink-faint:#757e92;
      --rule:#2a303c; --rule-soft:#232833; --accent:#8daedd;
      --crit:#e8798a; --high:#e39355; --med:#d4b04a; --low:#7fb295; --info:#96a0b2; --unknown:#8a93a5;
    }
  }
  *,*::before,*::after { box-sizing:border-box; }
  body { margin:0; background:var(--ground); color:var(--ink); font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; -webkit-font-smoothing:antialiased; }
  .wrap { max-width:1600px; margin:0 auto; padding:0 24px 72px; }
  a { color:var(--accent); text-underline-offset:.15em; }
  code { font-family:var(--mono); font-size:.86em; background:var(--surface-alt); border:1px solid var(--rule-soft); border-radius:3px; padding:.08em .34em; }
  h1 { font-size:clamp(1.7rem,4vw,2.4rem); line-height:1.12; margin:0; letter-spacing:-.015em; }
  h2 { font-size:1.4rem; margin:0 0 4px; padding-bottom:8px; border-bottom:2px solid var(--ink); letter-spacing:-.01em; }
  h3 { font-size:1rem; margin:0; line-height:1.35; }
  p { margin:0; }

  header.masthead { border-bottom:1px solid var(--rule); padding:44px 0 24px; display:flex; flex-direction:column; gap:12px; }
  .eyebrow { font-family:var(--mono); font-size:11px; letter-spacing:.13em; text-transform:uppercase; color:var(--ink-faint); }
  .meta-line { font-family:var(--mono); font-size:12px; color:var(--ink-faint); display:flex; flex-wrap:wrap; gap:4px 22px; }

  .cols { display:grid; grid-template-columns:260px minmax(0,1fr); gap:56px; align-items:start; padding-top:32px; }
  /* No rail to render -> ONE column. Without this the single <main> auto-places
     into the first track and the whole report renders 260px wide. That is not a
     hypothetical: a run with nothing confirmed and nothing needs-human has an
     empty rail, which is exactly the run that most needs to be readable. */
  .cols.norail { grid-template-columns:minmax(0,1fr); gap:0; }
  @media (max-width:939px) { .cols { grid-template-columns:1fr; gap:0; } .rail { display:none; } }
  .rail { position:sticky; top:20px; max-height:calc(100vh - 40px); overflow-y:auto; }
  .rail-title { font-family:var(--mono); font-size:11px; letter-spacing:.13em; text-transform:uppercase; color:var(--ink-faint); padding-bottom:8px; border-bottom:1px solid var(--rule); margin-bottom:10px; }
  .rail ol { list-style:none; margin:0; padding:0; display:flex; flex-direction:column; gap:2px; }
  .rail a { display:flex; align-items:baseline; gap:8px; padding:4px 6px; border-radius:4px; font-size:13px; line-height:1.3; color:var(--ink-soft); text-decoration:none; }
  .rail a:hover { background:var(--surface-alt); color:var(--ink); }
  .rail .rt { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }

  /* Belt and braces with the .norail rule: pin <main> to the LAST track so
     implicit placement can never put it in the rail's. */
  main { min-width:0; grid-column:-2; display:flex; flex-direction:column; gap:40px; }
  /* The page is wide so tables and flow diagrams can breathe; prose is not.
     A 1500px line of running text is unreadable, so paragraphs keep a measure. */
  .prose { max-width:78ch; }
  section { display:flex; flex-direction:column; gap:14px; scroll-margin-top:20px; }

  .band { display:grid; grid-template-columns:repeat(auto-fit,minmax(112px,1fr)); gap:1px; background:var(--rule); border:1px solid var(--rule); border-radius:6px; overflow:hidden; }
  .tile { background:var(--surface); padding:14px 16px 12px; display:flex; flex-direction:column; gap:2px; }
  .tile .n { font-size:1.9rem; font-weight:700; line-height:1; font-variant-numeric:tabular-nums; }
  .tile .k { font-family:var(--mono); font-size:10px; letter-spacing:.12em; text-transform:uppercase; color:var(--ink-faint); }
  .tile.c .n{color:var(--crit)} .tile.h .n{color:var(--high)} .tile.m .n{color:var(--med)} .tile.l .n{color:var(--low)} .tile.i .n{color:var(--info)}

  .dot { width:7px; height:7px; border-radius:50%; flex:0 0 auto; display:inline-block; align-self:center; background:var(--unknown); }
  .dot.c{background:var(--crit)} .dot.h{background:var(--high)} .dot.m{background:var(--med)} .dot.l{background:var(--low)} .dot.i{background:var(--info)}

  .find { background:var(--surface); border:1px solid var(--rule); border-left:4px solid var(--sev,var(--unknown)); border-radius:5px; padding:16px 20px 18px; display:flex; flex-direction:column; gap:10px; }
  .find.c{--sev:var(--crit)} .find.h{--sev:var(--high)} .find.m{--sev:var(--med)} .find.l{--sev:var(--low)} .find.i{--sev:var(--info)}
  .find-top { display:flex; flex-wrap:wrap; align-items:baseline; gap:10px; }
  .pill { font-family:var(--mono); font-size:10px; font-weight:700; letter-spacing:.1em; padding:2px 7px; border-radius:3px; color:var(--sev,var(--unknown)); border:1px solid var(--sev,var(--unknown)); }
  .find-top h3 { flex:1 1 240px; }
  .meta { font-family:var(--mono); font-size:11.5px; color:var(--ink-faint); word-break:break-word; }
  .msg { color:var(--ink-soft); }
  .anchor { font-family:var(--mono); font-size:11.5px; color:var(--ink-faint); word-break:break-all; }

  .chips { display:flex; flex-wrap:wrap; gap:6px; }
  .chip { font-family:var(--mono); font-size:10.5px; padding:2px 7px; border-radius:10px; background:var(--surface-alt); border:1px solid var(--rule); color:var(--ink-soft); }
  .chip.risk { font-weight:700; }
  .chip.kev { color:var(--crit); border-color:var(--crit); }
  .chip.reach { color:var(--med); border-color:var(--med); }

  .flow { display:flex; flex-wrap:wrap; align-items:stretch; gap:6px; }
  .node { background:var(--surface-alt); border:1px solid var(--rule); border-radius:6px; padding:6px 10px; min-width:118px; }
  .node.source { border-color:var(--high); } .node.sink { border-color:var(--crit); }
  .node .loc { font-family:var(--mono); font-size:11.5px; font-weight:600; }
  .node .sym { font-family:var(--mono); font-size:11px; color:var(--ink-faint); }
  .node .why { font-size:11px; color:var(--ink-faint); margin-top:2px; max-width:220px; }
  .arrow { align-self:center; color:var(--ink-faint); }

  .scenario { background:var(--surface-alt); border-radius:4px; padding:11px 14px; display:flex; flex-direction:column; gap:5px; }
  .s-label { font-family:var(--mono); font-size:10px; letter-spacing:.12em; text-transform:uppercase; color:var(--ink-faint); }
  .refs { font-size:11.5px; color:var(--ink-faint); word-break:break-all; }
  .fold-note { font-size:12.5px; color:var(--ink-faint); font-style:italic; }

  .chain { background:var(--surface); border:1px solid var(--crit); border-left:4px solid var(--crit); border-radius:5px; padding:16px 20px; display:flex; flex-direction:column; gap:8px; }
  .chain h3 { color:var(--crit); }
  .warn { background:var(--surface); border:1px solid var(--high); border-left:4px solid var(--high); border-radius:5px; padding:12px 16px; }
  .warn ul { margin:6px 0 0; padding-left:1.2em; }

  .tw { overflow-x:auto; border:1px solid var(--rule); border-radius:5px; background:var(--surface); }
  table { border-collapse:collapse; width:100%; font-size:13.5px; }
  th,td { text-align:left; padding:7px 12px; border-bottom:1px solid var(--rule-soft); vertical-align:top; }
  thead th { font-family:var(--mono); font-size:10px; font-weight:700; letter-spacing:.1em; text-transform:uppercase; color:var(--ink-faint); background:var(--surface-alt); border-bottom:1px solid var(--rule); white-space:nowrap; }
  tbody tr:last-child td { border-bottom:0; }
  td.at { font-family:var(--mono); font-size:12px; word-break:break-all; }
  tr.unexamined td { color:var(--high); }

  details { background:var(--surface); border:1px solid var(--rule); border-radius:5px; }
  details.members { background:transparent; border:0; }
  summary { cursor:pointer; padding:10px 16px; font-weight:600; font-size:14px; }
  details.members summary { padding:4px 0; font-weight:500; font-size:13px; color:var(--ink-faint); }
  details > *:not(summary) { padding:0 16px 14px; }
  details.members > *:not(summary) { padding:0; }

  footer { margin-top:56px; padding-top:18px; border-top:1px solid var(--rule); font-family:var(--mono); font-size:11.5px; color:var(--ink-faint); display:flex; flex-direction:column; gap:5px; }

  .banner { background:var(--surface); border:2px solid var(--crit); border-radius:6px; padding:16px 20px; display:flex; flex-direction:column; gap:8px; }
  .banner h2 { color:var(--crit); border-bottom:0; padding-bottom:0; font-size:1.15rem; }
  .banner code { background:var(--ground); }
  .banner .next { font-family:var(--mono); font-size:12px; color:var(--ink-soft); }

  .surfaces { display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); gap:14px; }
  .sf { background:var(--surface); border:1px solid var(--rule); border-radius:6px; padding:14px 16px; display:flex; flex-direction:column; gap:8px; }
  .sf.lead { border-color:var(--ink); }
  .sf-h { display:flex; align-items:baseline; justify-content:space-between; gap:10px; }
  .sf-h .t { font-weight:700; font-size:.95rem; }
  .sf-h .n { font-size:1.6rem; font-weight:700; line-height:1; font-variant-numeric:tabular-nums; }
  .sf-sub { font-family:var(--mono); font-size:11px; color:var(--ink-faint); }
  .sf-bar { display:flex; height:6px; border-radius:3px; overflow:hidden; background:var(--surface-alt); }
  .sf-bar span { display:block; }
  .sf-bar .c{background:var(--crit)} .sf-bar .h{background:var(--high)} .sf-bar .m{background:var(--med)} .sf-bar .l{background:var(--low)} .sf-bar .i{background:var(--info)}

  td.num { font-variant-numeric:tabular-nums; white-space:nowrap; }
  td.pkg { font-family:var(--mono); font-weight:600; word-break:break-all; }
  .sig { font-family:var(--mono); font-size:10.5px; }
  .sig .kev { color:var(--crit); font-weight:700; }
  .sig .tc { color:var(--ink-faint); }
  details.members ul { margin:4px 0 0; padding-left:1.1em; font-size:12.5px; }
  details.members li { margin:1px 0; }
`;

const AI_CSS = `
  .ai-narrative { border:1px solid var(--accent); border-radius:6px; padding:12px 18px; background:var(--surface); }
  .ai-tag { font-family:var(--mono); font-size:10px; letter-spacing:.1em; padding:2px 6px; border-radius:8px; border:1px solid var(--accent); color:var(--accent); vertical-align:middle; }
  .ai-note { color:var(--ink-faint); font-size:12px; font-style:italic; }
  .ai-fix { border-left:3px solid var(--accent); background:var(--surface-alt); padding:8px 12px; border-radius:0 4px 4px 0; }
  .ai-patch { background:var(--surface-alt); border:1px solid var(--rule); border-radius:4px; padding:8px 10px; overflow-x:auto; font-size:12px; margin:6px 0 0; }
  .ai-block { display:flex; flex-direction:column; gap:5px; }
`;

const SEV_KEY: Record<Severity, string> = { critical: "c", high: "h", medium: "m", low: "l", info: "i" };

export function renderHtml(d: Dossier, narrative?: Narrative): string {
  const c = d.manifest.counts.bySeverity;
  const rem = remediationMap(narrative);

  const byStatus = (st: Finding["status"]) => d.findings.filter((f) => f.status === st).sort(compareWithinStatus);
  const confirmed = byStatus("confirmed");
  const needsHuman = byStatus("needs-human");
  const open = byStatus("open");
  const dismissed = byStatus("dismissed");

  // EVERY tier splits dependencies out, decided ones included.
  //
  // The first cut only split the undecided tier, on the reasoning that
  // confirmed findings are few and already the answer. That reasoning does not
  // survive a finished audit: adjudicating one produced 351 confirmed, 151 of
  // them dependency advisories, and because the composite risk weights EPSS a
  // `pnpm-lock.yaml` CVE opened the section again — the exact complaint the
  // surface split exists to fix, one tier over. A confirmed advisory is still
  // worked as a ranked upgrade list, not read as a flow.
  const undecided = bySurface(open);
  const confirmedBy = bySurface(confirmed);
  const needsBy = bySurface(needsHuman);
  const unread = unadjudicatedCode(d.findings);

  // HIGH and above earn a card with their cross-file flow drawn; the rest go in
  // a table under a fold. On a real audit that is ~240 flows worth reading and
  // ~380 worth knowing about, and printing both the same way is what made the
  // first three screens unusable.
  const loud = (fs: readonly Finding[]) => fs.filter((f) => f.severity === "critical" || f.severity === "high");
  const quiet = (fs: readonly Finding[]) => fs.filter((f) => f.severity !== "critical" && f.severity !== "high");

  const actionable = [...confirmed, ...needsHuman];
  const railSections = [
    ...(unread.length ? [{ id: "incomplete", label: "Incomplete audit" }] : []),
    { id: "summary", label: "Summary" },
    ...(confirmed.length ? [{ id: "confirmed", label: `Confirmed (${confirmed.length})` }] : []),
    ...(needsHuman.length ? [{ id: "needs-human", label: `Needs human (${needsHuman.length})` }] : []),
    ...(undecided.code.length ? [{ id: "code", label: `Your source code (${undecided.code.length})` }] : []),
    ...(undecided.supply.length ? [{ id: "supply", label: `Secrets & config (${undecided.supply.length})` }] : []),
    ...(undecided.deps.length ? [{ id: "deps", label: `Dependencies (${undecided.deps.length})` }] : []),
    ...(dismissed.length ? [{ id: "dismissed", label: `Refuted (${dismissed.length})` }] : []),
    { id: "coverage", label: "Coverage" },
  ];

  const tiles = SEVERITIES.map((sev) => `<div class="tile ${SEV_KEY[sev]}"><span class="n">${c[sev] ?? 0}</span><span class="k">${sev}</span></div>`).join("");

  const section = (id: string, title: string, sub: string, body: string) =>
    body ? `\n  <section id="${id}"><h2>${esc(title)}</h2>${sub ? `<p class="msg prose">${esc(sub)}</p>` : ""}${body}</section>` : "";

  const foldedTable = (label: string, fs: readonly Finding[]) =>
    fs.length ? `<details><summary>${esc(label)} (${fs.length})</summary>${tableHtml(fs)}</details>` : "";

  const codeBody = undecided.code.length
    ? entryPointsHtml(undecided.code) + tierHtml(loud(undecided.code), rem) + foldedTable("Lower-severity candidates", quiet(undecided.code))
    : "";

  const supplyBody = undecided.supply.length ? tableHtml(loud(undecided.supply)) + foldedTable("Lower-severity findings", quiet(undecided.supply)) : "";

  // A tier's dependency half, rolled up per package under a fold — so a decided
  // advisory stays present and actionable without displacing the code findings.
  const depsFold = (fs: readonly Finding[], label: string) =>
    fs.length
      ? `<details><summary>${fs.length} dependency advisor${fs.length === 1 ? "y" : "ies"} ${esc(label)}, rolled up per package</summary>
      <p class="msg prose">Worked as a ranked upgrade list, not read as a flow. One row per package &mdash; the unit you actually bump.</p>
      ${depsHtml(fs)}</details>`
      : "";

  const depsBody = undecided.deps.length
    ? `<details><summary>Show ${undecided.deps.length} advisor${undecided.deps.length === 1 ? "y" : "ies"}, rolled up per package</summary>
      <p class="msg prose">One row per package &mdash; the unit you actually upgrade. Work the list in risk order and stop when the rest are below your bar:
        KEV first, then EPSS, then severity. Open a row to see its individual advisories.</p>
      ${depsHtml(undecided.deps)}</details>`
    : "";

  const tools = d.manifest.toolStatus?.length ? toolStatusLines(d.manifest.toolStatus).join(" \u00b7 ") : d.manifest.toolsRun.join(", ") || "none";
  const rail = railHtml(railSections, actionable);

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ultrasec \u2014 security audit</title>
<style>${CSS}${hasNarrativeContent(narrative) ? AI_CSS : ""}</style></head>
<body>
<div class="wrap">
  <header class="masthead">
    <div class="eyebrow">Security audit \u00b7 ultrasec ${esc(d.manifest.version)}</div>
    <h1>${esc(d.manifest.repo)}</h1>
    <div class="meta-line">
      <span>${d.manifest.counts.findings} candidate(s)</span>
      <span>${confirmed.length} confirmed</span>
      <span>${needsHuman.length} needs human</span>
      <span>${open.length} unadjudicated</span>
      <span>${dismissed.length} refuted</span>
    </div>
    <div class="meta-line"><span>tools: ${esc(tools)}</span></div>
  </header>
  <div class="cols${rail ? "" : " norail"}">
  ${rail}
  <main>${bannerHtml(unread)}
    <section id="summary">
      <h2>Summary</h2>
      ${surfacesHtml(undecided)}
      <div class="band">${tiles}</div>
    </section>${execSummaryHtml(narrative)}${chainsHtml(narrative)}${positivePatternsHtml(narrative)}${section(
      "confirmed",
      `Confirmed (${confirmed.length})`,
      "",
      confirmed.length ? tierHtml([...confirmedBy.code, ...confirmedBy.supply], rem) + depsFold(confirmedBy.deps, "confirmed") : "",
    )}${section(
      "needs-human",
      `Needs human review (${needsHuman.length})`,
      "Uncertain, and too severe to dismiss without proof.",
      needsHuman.length ? tierHtml([...needsBy.code, ...needsBy.supply], rem) + depsFold(needsBy.deps, "needing a decision") : "",
    )}${section(
      "code",
      `${SURFACE_TITLE.code} \u2014 undecided (${undecided.code.length})`,
      "Flows and unsafe operations in code this repository owns. Recall-oriented by design: each one is decided by opening the file and following the path, not from this page.",
      codeBody,
    )}${section(
      "supply",
      `${SURFACE_TITLE.supply} \u2014 undecided (${undecided.supply.length})`,
      "Credentials committed to the tree, CI workflows and infrastructure-as-code. Also this repository's own code, but read as a diff rather than a data-flow.",
      supplyBody,
    )}${section("deps", `${SURFACE_TITLE.deps} \u2014 undecided (${undecided.deps.length})`, "", depsBody)}${
      dismissed.length
        ? `\n  <section id="dismissed"><h2>Refuted (${dismissed.length})</h2>
      <details><summary>Show the ${dismissed.length} candidate(s) this audit refuted, and on what ground</summary>
      <p class="msg prose">Kept because an audit that hides its refutations cannot be checked. The <em>why</em> column names the ground and the argument that was made.</p>
      ${tableHtml(dismissed)}</details></section>`
        : ""
    }${rootCausesHtml(narrative)}${hardeningNotesHtml(narrative)}
    ${coverageHtml(d)}
    <footer>
      <span>ultrasec ${esc(d.manifest.version)} \u00b7 ${esc(d.manifest.generatedNote)}</span>
      <span>Every finding cites a resolvable file:line \u2014 \`ultrasec check\` fails the audit otherwise.</span>
    </footer>
  </main>
  </div>
</div>
</body></html>
`;
}
