import { mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { mergeGraphs, type Graph } from "./graph.js";
import { byStr, carryStageNotes, eprintln } from "./util.js";
import { redactSecrets } from "./redact.js";
import { SEVERITIES, type Finding, type Manifest, type Severity } from "./types.js";
import { proposedFor, renderProposalSummary } from "./noise.js";
import { sortFindings } from "./rank.js";

// The on-disk audit dossier — the hand-off between the deterministic engine and
// the AI. Plain JSON + a Markdown index, so it is reviewable and diffable.
export interface Dossier {
  manifest: Manifest;
  findings: Finding[];
  graph: Graph;
}

export function emptySeverityCounts(): Record<Severity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

/**
 * The severity histogram the manifest publishes.
 *
 * Guarded against a severity outside the vocabulary. `c[f.severity]++` on an
 * unknown key silently grows the record — a run that ingested eleven findings
 * with `severity: null` shipped a manifest reading `{"null": NaN}` alongside
 * five buckets that were eleven short, and announced a total that matched
 * neither. `makeToolFinding` now refuses such a finding at the door; this is the
 * second lock, because a corrupted count is a lie the whole report repeats and
 * no gate was checking it.
 */
export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const c = emptySeverityCounts();
  for (const f of findings) {
    if (Object.hasOwn(c, f.severity)) c[f.severity]++;
  }
  return c;
}

type DuplicateId = NonNullable<Manifest["duplicateIds"]>[number];

/**
 * One row per finding id.
 *
 * Every verdict, every `--apply` and every citation names a finding by its id,
 * so two rows sharing one are ambiguous: a verdict would land on whichever the
 * reader met first. That is why a duplicate used to be fatal — and why, after a
 * dependency adapter derived the same id for two sibling packages, every stage
 * after `scan` refused a 354-finding run over one pair.
 *
 * Kept: the first occurrence, unless a later one carries an adjudication and the
 * first does not — losing an auditor's verdict is worse than losing a
 * re-derivable scanner row. Each collapse is returned so the caller can say so.
 */
export function dedupeFindings(findings: Finding[]): { findings: Finding[]; duplicates: DuplicateId[] } {
  const kept = new Map<string, Finding>();
  const seen = new Map<string, { dropped: number; differing: boolean }>();
  for (const f of findings) {
    const prior = kept.get(f.id);
    if (!prior) {
      kept.set(f.id, f);
      continue;
    }
    const at = seen.get(f.id) ?? { dropped: 0, differing: false };
    at.dropped++;
    if (JSON.stringify(prior) !== JSON.stringify(f)) at.differing = true;
    seen.set(f.id, at);
    if (prior.status === "open" && f.status !== undefined && f.status !== "open") kept.set(f.id, f);
  }
  if (!seen.size) return { findings, duplicates: [] };
  const duplicates = [...seen].map(([id, s]) => ({ id, dropped: s.dropped, differing: s.differing })).sort((a, b) => byStr(a.id, b.id));
  return { findings: [...kept.values()], duplicates };
}

/** Fold this collapse into whatever the manifest already recorded, one entry per id. */
function recordDuplicates(prior: Manifest["duplicateIds"], next: DuplicateId[]): DuplicateId[] {
  const byId = new Map((prior ?? []).map((d) => [d.id, { ...d }]));
  for (const d of next) {
    const at = byId.get(d.id);
    if (at) {
      at.dropped += d.dropped;
      at.differing ||= d.differing;
    } else byId.set(d.id, { ...d });
  }
  return [...byId.values()].sort((a, b) => byStr(a.id, b.id));
}

function warnDuplicates(duplicates: DuplicateId[]): void {
  const rows = duplicates.reduce((n, d) => n + d.dropped, 0);
  const differing = duplicates.filter((d) => d.differing).map((d) => d.id);
  eprintln(
    `ultrasec: ✗ dropped ${rows} duplicate finding row(s) from findings.json — ${duplicates.map((d) => d.id).join(", ")}. Kept one row per id (an adjudicated one when there was one); recorded in manifest.duplicateIds.${
      differing.length ? ` Rows with different content were lost for: ${differing.join(", ")} — the id derivation collided, re-scan once it is fixed.` : ""
    }`,
  );
}

export function writeDossier(outDir: string, d: Dossier): void {
  // The invariant lives at the writer: whatever a stage produced, the file on
  // disk never carries two rows with one id.
  const { findings, duplicates } = dedupeFindings(d.findings);
  let manifest = d.manifest;
  if (duplicates.length) {
    warnDuplicates(duplicates);
    manifest = {
      ...manifest,
      duplicateIds: recordDuplicates(manifest.duplicateIds, duplicates),
      counts: { findings: findings.length, bySeverity: countBySeverity(findings) },
    };
  }
  d = { ...d, manifest, findings };
  mkdirSync(outDir, { recursive: true });
  writeFileSync(join(outDir, "manifest.json"), JSON.stringify(d.manifest, null, 2));
  writeFileSync(join(outDir, "findings.json"), JSON.stringify(d.findings, null, 2));
  writeFileSync(join(outDir, "graph.json"), JSON.stringify(d.graph, null, 2));
  writeFileSync(join(outDir, "DOSSIER.md"), renderDossierMd(d));
}

/**
 * Fold a scoped/incremental pass (`next`) into an existing run (`prev`).
 *  - findings already adjudicated in `prev` (status ≠ open) keep their lifecycle
 *    (status/verdict/exploitPath/confidence and the stage notes in their message)
 *    but refresh their deterministic fields — the engine's message included —
 *    from `next`;
 *  - genuinely new findings are appended;
 *  - findings only in `prev` (outside this pass's scope) are KEPT — a scoped
 *    re-scan must never delete what it didn't look at.
 * Idempotent and order-independent (findings keyed by content-hash id).
 */
/**
 * Carry a prior adjudication onto a freshly-scanned finding, keeping `next`'s
 * deterministic fields (severity, path, risk).
 *
 * Every field an adjudicator AUTHORS has to be listed here, and the list used to
 * be written out twice — here and in `import`. Both copies named
 * status/verdict/exploitPath/confidence/message and both omitted `brocard` and
 * `fixedIn`, so a `scan --merge` silently erased the named ground of every
 * refutation and the commit a fix was folded in at. `check --semantic` then
 * reported those dismissals as naming no ground, which is the audit trail
 * accusing the auditor of the tool's own data loss.
 *
 * One function, one list: a new authored field is added once and both callers
 * get it.
 *
 * `message` is half authored, half not: the engine's prose and evidence, then
 * the stage notes the applies appended. Only the notes are carried — see
 * `carryStageNotes` for the hash that survived its own detector's fix when the
 * whole old message was kept.
 */
export function preserveAdjudication(next: Finding, old: Finding): Finding {
  const merged: Finding = {
    ...next,
    status: old.status,
    verdict: old.verdict,
    exploitPath: old.exploitPath === undefined ? undefined : redactSecrets(old.exploitPath),
    confidence: old.confidence,
    message: carryStageNotes(next.message, old.message),
  };
  // Optional authored fields: only set when present, so a merge never
  // introduces an explicit `undefined` the JSON round-trip would drop anyway.
  if (old.brocard) merged.brocard = old.brocard;
  if (old.fixedIn) merged.fixedIn = old.fixedIn;
  // Blame is opt-in (`--blame`): a scoped re-scan run without it would otherwise
  // erase the commit `revalidate` counts "commits since the finding" from.
  if (!next.provenance && old.provenance) merged.provenance = old.provenance;
  return merged;
}

export function mergeDossier(prev: Dossier, next: Dossier): Dossier {
  const byId = new Map<string, Finding>();
  for (const f of prev.findings) byId.set(f.id, f);
  for (const f of next.findings) {
    const old = byId.get(f.id);
    if (old && old.status !== "open") {
      // preserve adjudication; keep `next`'s deterministic fields (severity/path/risk).
      byId.set(f.id, preserveAdjudication(f, old));
    } else {
      byId.set(f.id, f);
    }
  }
  const findings = [...byId.values()].sort((a, b) => byStr(a.id, b.id));

  const graph = mergeGraphs(prev.graph, next.graph);

  const scopes = [...new Set([...(prev.manifest.scopes ?? []), ...(next.manifest.scopes ?? [])])].sort(byStr);
  // Truncation reflects what the MERGED dossier still omits:
  //  - a SCOPED pass (next has scopes) only re-covered part of the repo, so prev's
  //    cap still applies to the rest → carry it forward (union);
  //  - a FULL re-scan (no scopes) is authoritative for the whole repo, so its own
  //    truncation wins — a complete, uncapped pass CLEARS a stale prior cap.
  const pt = prev.manifest.truncation;
  const nt = next.manifest.truncation;
  const nextScoped = !!(next.manifest.scopes && next.manifest.scopes.length);
  const truncation = nextScoped
    ? pt || nt
      ? {
          candidates: Math.max(pt?.candidates ?? 0, nt?.candidates ?? 0),
          total: Math.max(pt?.total ?? 0, nt?.total ?? 0),
          ...(pt?.files || nt?.files ? { files: true as const } : {}),
        }
      : undefined
    : nt;
  // Per-tool status unions by name, next winning on conflict — so a scoped pass
  // that re-ran only trivy updates trivy without wiping the other tools' outcomes.
  const statusByName = new Map<string, NonNullable<Manifest["toolStatus"]>[number]>();
  for (const s of prev.manifest.toolStatus ?? []) statusByName.set(s.name, s);
  for (const s of next.manifest.toolStatus ?? []) statusByName.set(s.name, s);
  const toolStatus = [...statusByName.values()];

  // A scoped/diff pass that skipped tools (and so never regenerated the SBOM)
  // must not lose the prior run's deliverable — carry it forward; a fresh SBOM
  // (next) wins on conflict, same precedence as toolStatus above.
  const sbom = next.manifest.sbom ?? prev.manifest.sbom;

  const manifest: Manifest = {
    ...next.manifest,
    languages: [...new Set([...prev.manifest.languages, ...next.manifest.languages])].sort(),
    toolsRun: [...new Set([...prev.manifest.toolsRun, ...next.manifest.toolsRun])].sort(),
    ...(toolStatus.length ? { toolStatus } : {}),
    counts: { findings: findings.length, bySeverity: countBySeverity(findings) },
    ...(truncation ? { truncation } : { truncation: undefined }),
    ...(scopes.length ? { scopes } : {}),
    ...(sbom ? { sbom } : {}),
  };

  return { manifest, findings, graph };
}

export function loadDossier(outDir: string): Dossier {
  const read = (name: string) => JSON.parse(readFileSync(join(outDir, name), "utf8"));
  if (!existsSync(join(outDir, "findings.json"))) {
    throw new Error(`no audit dossier at ${outDir} (run \`ultrasec scan --out ${outDir}\` first)`);
  }
  const findings: unknown = read("findings.json");
  if (!Array.isArray(findings)) throw new Error("findings.json must contain a JSON array");
  for (const [index, finding] of findings.entries()) {
    if (!finding || typeof finding !== "object" || typeof finding.id !== "string" || !finding.id.trim()) {
      throw new Error(`findings.json row ${index + 1} requires a non-empty string id`);
    }
  }
  // A missing id is unreadable; a repeated one is not. Collapse it, say so, and
  // carry the record in the manifest so the next write persists it.
  const manifest: Manifest = read("manifest.json");
  const { findings: unique, duplicates } = dedupeFindings(findings as Finding[]);
  if (!duplicates.length) return { manifest, findings: unique, graph: read("graph.json") };
  warnDuplicates(duplicates);
  return {
    manifest: {
      ...manifest,
      duplicateIds: recordDuplicates(manifest.duplicateIds, duplicates),
      ...(manifest.counts ? { counts: { findings: unique.length, bySeverity: countBySeverity(unique) } } : {}),
    },
    findings: unique,
    graph: read("graph.json"),
  };
}

function severityBadge(s: Severity): string {
  return { critical: "🟥 CRIT", high: "🟧 HIGH", medium: "🟨 MED", low: "🟩 LOW", info: "⬜ INFO" }[s];
}

/** "provenance: <author> · <date> · owner <team>" — only the fields present. */
/** "v0.6.6 `package-lock.json:1` · v6.5.2 `app/package-lock.json:1`" — the
 *  per-instance evidence of a cross-version-merged dep advisory. */
export function locationsLine(locations: NonNullable<Finding["locations"]>): string {
  return locations.map((e) => `${e.version ? `v${e.version} ` : ""}\`${e.file}${e.line !== undefined ? `:${e.line}` : ""}\``).join(" · ");
}

/** "trivy: ran (3) · osv-scanner: skipped — no target files" — per-tool outcomes. */
export function toolStatusLines(status: NonNullable<Manifest["toolStatus"]>): string[] {
  return status.map((s) => {
    const count = typeof s.findings === "number" && (s.status === "ran" || s.status === "empty") ? ` (${s.findings})` : "";
    const why = s.note && (s.status === "skipped" || s.status === "failed") ? ` — ${s.note}` : "";
    // A pass that succeeded over less than it could have must not read as a full one.
    const degraded = s.degraded && (s.status === "ran" || s.status === "empty") ? ` — ⚠️ degraded: ${s.degraded}` : "";
    return `${s.name}: ${s.status}${count}${why}${degraded}`;
  });
}

export function provenanceLine(f: Finding): string {
  const p = f.provenance;
  if (!p) return "";
  const who = [p.author, p.date].filter(Boolean).join(" · ");
  const bits = [who, p.commit ? `@${p.commit}` : "", p.owner ? `owner ${p.owner}` : ""].filter(Boolean);
  return bits.length ? `provenance: ${bits.join(" · ")}` : "";
}

/** A compact, always-loadable index of the run — the AI reads THIS, not graph.json. */
export function renderDossierMd(d: Dossier): string {
  const { manifest: m, findings } = d;
  const c = m.counts.bySeverity;
  const L: string[] = [];
  L.push(`# ultrasec audit dossier`);
  L.push("");
  L.push(`- repo: \`${m.repo}\``);
  L.push(`- languages: ${m.languages.join(", ") || "—"}`);
  L.push(`- external tools run: ${m.toolsRun.join(", ") || "none (graph + taint only)"}`);
  if (m.toolStatus?.length) for (const line of toolStatusLines(m.toolStatus)) L.push(`  - ${line}`);
  if (m.scannerPolicy)
    L.push(
      `- required scanners (this pass): ${m.scannerPolicy.complete ? "complete" : `INCOMPLETE — ${m.scannerPolicy.incomplete.join(", ")}`} — execution only, not a clean-security verdict`,
    );
  if (m.sbom) L.push(`- SBOM: \`${m.sbom}\` (CycloneDX)`);
  L.push(`- findings: **${m.counts.findings}** — ${SEVERITIES.map((s) => `${severityBadge(s)} ${c[s]}`).join("  ")}`);
  L.push("");
  L.push(`> Candidates are deterministic and **recall-oriented** — every one needs`);
  L.push(`> adjudication. Open each with \`ultrasec dossier <id>\` (real code + the`);
  L.push(`> cross-file path), confirm whether the flow is real and exploitable, then`);
  L.push(`> record a verdict via \`ultrasec verify\`. An uncertain high-severity stays`);
  L.push(`> **needs-human** — never silently dropped.`);
  L.push("");

  if (m.truncation?.candidates) {
    // Report the OMITTED count (accurate to what the cap dropped) rather than a
    // "shown = total − candidates" that can drift from the merged finding set.
    // The remediation sentence is command-specific: scan's default names
    // --max-candidates/--budget/--scope (all real scan flags); a command whose
    // cap isn't reachable through those flags (e.g. `logs`'s fixed per-family
    // cap) supplies its own `truncation.hint` instead — never both.
    const advice = m.truncation.hint ?? "Raise `--max-candidates` (or `--budget thorough`) or narrow `--scope` to see the rest.";
    L.push(`> ⚠️ **Coverage capped:** **${m.truncation.candidates}** of **${m.truncation.total}** candidate(s) were not enumerated. ${advice}`);
    L.push("");
  }
  if (m.truncation?.files) {
    L.push(`> ⚠️ **Partial walk:** the file walk hit \`--max-files\` — some files were **not scanned**. Raise \`--max-files\` or narrow \`--scope\`.`);
    L.push("");
  }
  if (m.scopes && m.scopes.length) {
    L.push(
      `> 🔎 **Scoped run** — only these paths were analysed: ${m.scopes.map((s) => `\`${s}\``).join(", ")}. Findings outside this scope are not represented.`,
    );
    L.push("");
  }

  if (!findings.length) {
    L.push(`_No candidate findings._`);
    return L.join("\n") + "\n";
  }

  // The de-noised families, named once each before the per-candidate list.
  // Presence-gated, so a run with no demotions renders byte-identically.
  //
  // Without it the reader meets 46 separate "untrusted input reaches query()"
  // entries and has to infer, one at a time, that they are the same test
  // harness. Naming the class once — with its ground and its members — is the
  // whole of the grouping this design does: reading, never verdicts.
  L.push(...renderProposalSummary(findings.map((f) => ({ id: f.id, proposed: proposedFor(f) }))));

  L.push(`## Candidates`);
  L.push("");
  // What the audit has DECIDED first, then highest composite risk, so the AI
  // adjudicates what matters most early and never re-reads its own refutations
  // ahead of what it confirmed. One comparator for the dossier, the Markdown
  // report and the HTML — see `rank.ts` for why they must not drift apart.
  const ordered = sortFindings(findings);
  for (const f of ordered) {
    L.push(`### ${f.id} — ${severityBadge(f.severity)} ${f.title}`);
    L.push("");
    const src = f.sources && f.sources.length > 1 ? ` · agreed by ${f.sources.join(", ")}` : f.tool !== "ultrasec" ? ` · via ${f.tool}` : "";
    L.push(`- category: ${f.category}${f.cwe ? ` · ${f.cwe}` : ""} · confidence ${f.confidence} · status ${f.status}${src}`);
    const risk: string[] = [];
    if (typeof f.risk === "number") risk.push(`risk ${f.risk}`);
    if (typeof f.epss === "number") risk.push(`EPSS ${(f.epss * 100).toFixed(1)}%`);
    if (f.kev) risk.push(`🚨 CISA KEV${f.kevDateAdded ? ` (${f.kevDateAdded})` : ""}`);
    if (f.verified) risk.push(`✅ verified secret`);
    if (risk.length) L.push(`- ${risk.join(" · ")}`);
    if (f.path && f.path.length) {
      L.push(`- path: ${f.path.map((p) => `\`${p.file}:${p.line}\``).join(" → ")}`);
    } else if (f.sink) {
      L.push(`- at: \`${f.sink.file}:${f.sink.line}\``);
    }
    if (f.locations?.length) L.push(`- affects: ${locationsLine(f.locations)}`);
    const prov = provenanceLine(f);
    if (prov) L.push(`- ${prov}`);
    L.push(`- ${f.message}`);
    L.push("");
  }
  L.push(`---`);
  L.push(`Engine: ultrasec ${m.version}. ${m.generatedNote}`);
  return L.join("\n") + "\n";
}
