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
  // Carry truncation forward: if EITHER pass was coverage-capped, the merged run is
  // still incomplete — never let a merge silently present a capped run as complete.
  const pt = prev.manifest.truncation;
  const nt = next.manifest.truncation;
  const truncation =
    pt || nt
      ? {
          candidates: Math.max(pt?.candidates ?? 0, nt?.candidates ?? 0),
          total: Math.max(pt?.total ?? 0, nt?.total ?? 0),
          ...(pt?.files || nt?.files ? { files: true as const } : {}),
        }
      : undefined;
  const manifest: Manifest = {
    ...next.manifest,
    languages: [...new Set([...prev.manifest.languages, ...next.manifest.languages])].sort(),
    toolsRun: [...new Set([...prev.manifest.toolsRun, ...next.manifest.toolsRun])].sort(),
    counts: { findings: findings.length, bySeverity: countBySeverity(findings) },
    ...(truncation ? { truncation } : { truncation: undefined }),
    ...(scopes.length ? { scopes } : {}),
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
  L.push(`- findings: **${m.counts.findings}** — ${SEVERITIES.map((s) => `${severityBadge(s)} ${c[s]}`).join("  ")}`);
  L.push("");
  L.push(`> Candidates are deterministic and **recall-oriented** — every one needs`);
  L.push(`> adjudication. Open each with \`ultrasec dossier <id>\` (real code + the`);
  L.push(`> cross-file path), confirm whether the flow is real and exploitable, then`);
  L.push(`> record a verdict via \`ultrasec verify\`. An uncertain high-severity stays`);
  L.push(`> **needs-human** — never silently dropped.`);
  L.push("");

  if (m.truncation?.candidates) {
    const shown = m.truncation.total - m.truncation.candidates;
    L.push(`> ⚠️ **Coverage capped:** showing the top **${shown}** of **${m.truncation.total}** taint candidates — **${m.truncation.candidates} not shown**. Raise \`--max-candidates\` (or \`--budget thorough\`) or narrow \`--scope\` to see the rest.`);
    L.push("");
  }
  if (m.truncation?.files) {
    L.push(`> ⚠️ **Partial walk:** the file walk hit \`--max-files\` — some files were **not scanned**. Raise \`--max-files\` or narrow \`--scope\`.`);
    L.push("");
  }
  if (m.scopes && m.scopes.length) {
    L.push(`> 🔎 **Scoped run** — only these paths were analysed: ${m.scopes.map((s) => `\`${s}\``).join(", ")}. Findings outside this scope are not represented.`);
    L.push("");
  }

  if (!findings.length) {
    L.push(`_No candidate findings._`);
    return L.join("\n") + "\n";
  }

  L.push(`## Candidates`);
  L.push("");
  // Highest composite risk first so the AI adjudicates what matters most early.
  const ordered = findings
    .slice()
    .sort((a, b) => (b.risk ?? -1) - (a.risk ?? -1) || SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));
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
    L.push(`- ${f.message}`);
    L.push("");
  }
  L.push(`---`);
  L.push(`Engine: ultrasec ${m.version}. ${m.generatedNote}`);
  return L.join("\n") + "\n";
}
