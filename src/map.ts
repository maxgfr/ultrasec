import { join } from "node:path";
import { readText } from "./walk.js";
import type { RepoScan } from "./scan.js";
import { langForFile } from "./lang.js";
import { findSinks, findSources } from "./catalog.js";
import { byStr } from "./util.js";
import { SEVERITIES, type Severity } from "./types.js";

// The cheap "threat-model" pass: enumerate the attack surface (where untrusted
// input enters, what dangerous sinks exist, and where they cluster) WITHOUT the
// expensive cross-file taint BFS or any external tools. O(files), no network — so
// it stays fast even on a billion-line monorepo and gives the AI a map to pick
// scoped targets from. Deterministic.

const SEV_WEIGHT: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const MAX_SAMPLES = 8;

export interface EntryPoint {
  file: string;
  line: number;
  kind: string;
  title: string;
}
export interface EntryGroup {
  kind: string;
  count: number;
  samples: EntryPoint[];
}
export interface SinkSummary {
  kind: string;
  cwe: string;
  severity: Severity;
  count: number;
  samples: { file: string; line: number; callee: string }[];
}
export interface LangSummary {
  lang: string;
  files: number;
  sources: number;
  sinks: number;
}
export interface DirSummary {
  dir: string;
  files: number;
  sources: number;
  sinks: number;
  /** Severity-weighted sink density — the prioritization signal. */
  score: number;
}
export interface TargetSuggestion {
  scope: string;
  sinks: number;
  sources: number;
  score: number;
  /** True when a prior run already scanned this scope (manifest.scopes). */
  covered: boolean;
  reason: string;
}
export interface AttackSurface {
  totals: { files: number; sources: number; sinks: number; truncated: boolean };
  entryPoints: EntryGroup[];
  sinks: SinkSummary[];
  byLanguage: LangSummary[];
  byTopDir: DirSummary[];
  /** Deterministic default order the AI may override — highest-value scopes first. */
  suggestedTargets: TargetSuggestion[];
}

function topDir(rel: string): string {
  const i = rel.indexOf("/");
  return i === -1 ? "." : rel.slice(0, i);
}

/** Build the attack-surface map. `coveredScopes` marks targets a prior run handled. */
export function buildAttackSurface(scan: RepoScan, coveredScopes: string[] = []): AttackSurface {
  const covered = new Set(coveredScopes);
  const entryByKind = new Map<string, EntryPoint[]>();
  const sinkByKind = new Map<string, SinkSummary>();
  const langAgg = new Map<string, LangSummary>();
  const dirAgg = new Map<string, DirSummary>();
  let totalSources = 0;
  let totalSinks = 0;

  for (const f of scan.files) {
    const lang = langForFile(f.rel);
    if (!lang) continue;
    const dir = topDir(f.rel);
    const la = langAgg.get(f.lang) ?? langAgg.set(f.lang, { lang: f.lang, files: 0, sources: 0, sinks: 0 }).get(f.lang)!;
    const da = dirAgg.get(dir) ?? dirAgg.set(dir, { dir, files: 0, sources: 0, sinks: 0, score: 0 }).get(dir)!;
    la.files++;
    da.files++;

    const sources = findSources(lang, readText(join(scan.repo, f.rel)));
    for (const s of sources) {
      totalSources++;
      la.sources++;
      da.sources++;
      const arr = entryByKind.get(s.kind) ?? entryByKind.set(s.kind, []).get(s.kind)!;
      arr.push({ file: f.rel, line: s.line, kind: s.kind, title: s.title });
    }

    for (const sink of findSinks(lang, f.calls)) {
      totalSinks++;
      la.sinks++;
      da.sinks++;
      da.score += SEV_WEIGHT[sink.severity];
      const ss =
        sinkByKind.get(sink.kind) ??
        sinkByKind.set(sink.kind, { kind: sink.kind, cwe: sink.cwe, severity: sink.severity, count: 0, samples: [] }).get(sink.kind)!;
      ss.count++;
      if (ss.samples.length < MAX_SAMPLES) ss.samples.push({ file: f.rel, line: sink.line, callee: sink.callee });
    }
  }

  const entryPoints: EntryGroup[] = [...entryByKind.entries()]
    .sort((a, b) => byStr(a[0], b[0]))
    .map(([kind, eps]) => {
      const sorted = eps.sort((a, b) => byStr(a.file, b.file) || a.line - b.line);
      return { kind, count: sorted.length, samples: sorted.slice(0, MAX_SAMPLES) };
    });

  const sinks = [...sinkByKind.values()].sort(
    (a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || b.count - a.count || byStr(a.kind, b.kind),
  );
  for (const s of sinks) s.samples.sort((a, b) => byStr(a.file, b.file) || a.line - b.line);

  const byLanguage = [...langAgg.values()].sort((a, b) => byStr(a.lang, b.lang));
  const byTopDir = [...dirAgg.values()].sort((a, b) => b.score - a.score || b.sinks - a.sinks || byStr(a.dir, b.dir));

  // Suggested targets: dirs with attack surface, highest severity-weighted density
  // first. The AI is free to override; un-covered targets are surfaced for the loop.
  const suggestedTargets: TargetSuggestion[] = byTopDir
    .filter((d) => d.sinks > 0 || d.sources > 0)
    .map((d) => ({
      scope: d.dir,
      sinks: d.sinks,
      sources: d.sources,
      score: d.score,
      covered: covered.has(d.dir),
      reason: `${d.sinks} sink(s), ${d.sources} entry point(s) across ${d.files} file(s)`,
    }));

  return {
    totals: { files: scan.files.length, sources: totalSources, sinks: totalSinks, truncated: !!scan.truncated },
    entryPoints,
    sinks,
    byLanguage,
    byTopDir,
    suggestedTargets,
  };
}

/** A compact, agent-readable threat-model summary. */
export function renderMapMd(repo: string, s: AttackSurface): string {
  const L: string[] = [];
  L.push(`# ultrasec attack-surface map`);
  L.push("");
  L.push(`- repo: \`${repo}\``);
  L.push(`- files: ${s.totals.files} · entry points: ${s.totals.sources} · sinks: ${s.totals.sinks}`);
  if (s.totals.truncated) L.push(`- ⚠️ partial walk (\`--max-files\` hit) — some files were not mapped.`);
  L.push("");
  L.push(`> The cheap recon pass: WHERE untrusted input enters and WHAT dangerous sinks`);
  L.push(`> exist — no taint BFS, no tools, no network. Use it to pick \`--scope\` targets,`);
  L.push(`> then \`ultrasec scan --scope <dir> --merge\` to drill in. The order below is a`);
  L.push(`> deterministic suggestion — override it with your own judgement.`);
  L.push("");

  L.push(`## Suggested targets (highest attack-surface density first)`);
  L.push("");
  if (!s.suggestedTargets.length) {
    L.push(`_No sources or sinks detected._`);
  } else {
    for (const t of s.suggestedTargets) {
      L.push(`- ${t.covered ? "✅" : "▢"} \`${t.scope}\` — ${t.reason}${t.covered ? " · already scanned" : ""}`);
    }
    const next = s.suggestedTargets.find((t) => !t.covered);
    if (next) {
      L.push("");
      L.push(`**Next:** \`ultrasec scan --repo ${repo} --scope ${next.scope} --merge --out <run>\``);
    }
  }
  L.push("");

  L.push(`## Entry points (untrusted input)`);
  L.push("");
  if (!s.entryPoints.length) L.push(`_None detected._`);
  for (const g of s.entryPoints) {
    L.push(`- **${g.kind}** (${g.count}): ${g.samples.map((e) => `\`${e.file}:${e.line}\``).join(", ")}${g.count > g.samples.length ? " …" : ""}`);
  }
  L.push("");

  L.push(`## Sinks by class`);
  L.push("");
  if (!s.sinks.length) L.push(`_None detected._`);
  for (const k of s.sinks) {
    L.push(
      `- **${k.kind}** (${k.cwe}, ${k.severity}) ×${k.count}: ${k.samples.map((x) => `\`${x.file}:${x.line}\``).join(", ")}${k.count > k.samples.length ? " …" : ""}`,
    );
  }
  L.push("");

  L.push(`## By language`);
  L.push("");
  for (const l of s.byLanguage) L.push(`- ${l.lang}: ${l.files} file(s), ${l.sources} entry point(s), ${l.sinks} sink(s)`);
  L.push("");
  return L.join("\n") + "\n";
}
