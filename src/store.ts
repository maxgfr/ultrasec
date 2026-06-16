import { mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import type { Graph } from "./graph.js";
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

  if (!findings.length) {
    L.push(`_No candidate findings._`);
    return L.join("\n") + "\n";
  }

  L.push(`## Candidates`);
  L.push("");
  for (const f of findings) {
    L.push(`### ${f.id} — ${severityBadge(f.severity)} ${f.title}`);
    L.push("");
    L.push(`- category: ${f.category}${f.cwe ? ` · ${f.cwe}` : ""} · confidence ${f.confidence} · status ${f.status}${f.tool !== "ultrasec" ? ` · via ${f.tool}` : ""}`);
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
