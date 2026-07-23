import { mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { mergeGraphs, type Graph } from "./graph.js";
import { byStr } from "./util.js";
import { SEVERITIES, type Finding, type Manifest, type Severity } from "./types.js";

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

export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const c = emptySeverityCounts();
  for (const f of findings) c[f.severity]++;
  return c;
}

export function writeDossier(outDir: string, d: Dossier): void {
  mkdirSync(outDir, { recursive: true });
  writeFileSync(join(outDir, "manifest.json"), JSON.stringify(d.manifest, null, 2));
  writeFileSync(join(outDir, "findings.json"), JSON.stringify(d.findings, null, 2));
  writeFileSync(join(outDir, "graph.json"), JSON.stringify(d.graph, null, 2));
  writeFileSync(join(outDir, "DOSSIER.md"), renderDossierMd(d));
}

/**
 * Fold a scoped/incremental pass (`next`) into an existing run (`prev`).
 *  - findings already adjudicated in `prev` (status ≠ open) keep their lifecycle
 *    (status/verdict/exploitPath/confidence/edited message) but refresh their
 *    deterministic fields from `next`;
 *  - genuinely new findings are appended;
 *  - findings only in `prev` (outside this pass's scope) are KEPT — a scoped
 *    re-scan must never delete what it didn't look at.
 * Idempotent and order-independent (findings keyed by content-hash id).
 */
export function mergeDossier(prev: Dossier, next: Dossier): Dossier {
  const byId = new Map<string, Finding>();
  for (const f of prev.findings) byId.set(f.id, f);
  for (const f of next.findings) {
    const old = byId.get(f.id);
    if (old && old.status !== "open") {
      // preserve adjudication; keep `next`'s deterministic fields (severity/path/risk).
      byId.set(f.id, {
        ...f,
        status: old.status,
        verdict: old.verdict,
        exploitPath: old.exploitPath,
        confidence: old.confidence,
        message: old.message,
      });
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
  return { manifest: read("manifest.json"), findings: read("findings.json"), graph: read("graph.json") };
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
    return `${s.name}: ${s.status}${count}${why}`;
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

  L.push(`## Candidates`);
  L.push("");
  // Highest composite risk first so the AI adjudicates what matters most early.
  const ordered = findings.slice().sort((a, b) => (b.risk ?? -1) - (a.risk ?? -1) || SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));
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
