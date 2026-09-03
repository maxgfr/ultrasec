import { join } from "node:path";
import { readText } from "./walk.js";
import { detectWorkspaces } from "./vendor/codeindex-engine.mjs";
import type { RepoScan } from "./scan.js";
import { localDefNames } from "./scan.js";
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
/** Entry points retained per kind. Larger than MAX_SAMPLES because the context
 *  scaffold reads this list and applies its own, larger cap — an 8-per-kind cut
 *  here was the binding constraint, and it made `context` report eight routes on
 *  a repo with dozens. `renderMapMd` still prints MAX_SAMPLES of them. */
const MAX_ENTRY_SAMPLES = 64;
/**
 * What one entry point contributes to a region's rank, on the same scale as
 * SEV_WEIGHT, by KIND.
 *
 * The score used to count sinks ONLY, so a directory full of internet-reachable
 * routes and no local sink scored 0 and sorted last — which is how a batch-job
 * directory came to outrank an entire authenticated web surface in the
 * `investigate` worklist.
 *
 * The kinds are not interchangeable, either. An HTTP route is reachable by
 * anyone; an environment read presumes the operator of the deployment is the
 * attacker, which is a real threat model but a much narrower one — it is why
 * `--no-env-sources` exists. Ranking them equally let configuration reads crowd
 * out routes in a capped list. HTTP and the cross-origin kinds sit between a
 * `high` sink (3) and a `critical` one (4); env/cli sit at the bottom.
 */
export const ENTRY_WEIGHT: Record<string, number> = {
  http: 3,
  ws: 3,
  dom: 2,
  postmessage: 2,
  llm: 2,
  stdin: 1,
  cli: 1,
  env: 1,
};
/** Kinds not in the table are unknown, not harmless — rank them with `cli`. */
export const DEFAULT_ENTRY_WEIGHT = 1;
export const entryWeight = (kind: string): number => ENTRY_WEIGHT[kind] ?? DEFAULT_ENTRY_WEIGHT;

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
/**
 * One file's attack surface. `EntryGroup.samples` and `SinkSummary.samples` are
 * capped for DISPLAY (8 per kind); anything that has to *choose* files — the
 * `investigate` region worklist above all — needs the full set, ranked. Reading
 * the samples instead meant a region's file list was a sample of a sample, and
 * because it was then sorted alphabetically the first sub-directory in the
 * alphabet consumed the entire budget: on a monorepo, `targets/alert-cli/**`
 * took all 8 slots and `targets/frontend/**` — the only component an anonymous
 * attacker could reach — never appeared at all.
 */
export interface FileSurface {
  file: string;
  region: string;
  sources: number;
  sinks: number;
  /** Severity-weighted sinks ⊕ entry points — the ranking key. */
  score: number;
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
  /** Every file carrying surface, ranked (highest first). Unsampled. */
  byFile: FileSurface[];
  /** Deterministic default order the AI may override — highest-value scopes first. */
  suggestedTargets: TargetSuggestion[];
}

function topDir(rel: string): string {
  const i = rel.indexOf("/");
  return i === -1 ? "." : rel.slice(0, i);
}

/**
 * How a repo is carved into regions: the workspace package a file belongs to,
 * falling back to its top-level directory.
 *
 * The first path segment is the right answer for a single-package repo and the
 * wrong one for every monorepo, where it collapses each workspace — a web app,
 * a CLI, two batch pipelines — into ONE region under a shared parent like
 * `targets/` or `packages/`. `detectWorkspaces` is the engine's own detector and
 * covers npm/pnpm/lerna/nx/cargo/go/maven/uv/composer/gradle, so this is not a
 * JavaScript special case.
 */
export function regionKeyer(repo: string): (rel: string) => string {
  let dirs: string[] = [];
  try {
    dirs = detectWorkspaces(repo)
      .packages.map((w) => w.dir.replace(/\\/g, "/").replace(/^\.\//, "").replace(/\/+$/, ""))
      .filter((d) => d && d !== ".")
      // Longest first: a nested package must win over its parent.
      .sort((a, b) => b.length - a.length || byStr(a, b));
  } catch {
    /* not a workspace, or unreadable — top-level directories it is */
  }
  if (!dirs.length) return topDir;
  return (rel) => dirs.find((d) => rel.startsWith(`${d}/`)) ?? topDir(rel);
}

/**
 * Re-order so every file's FIRST entry point comes before any file's second, its
 * second before any third, and so on — preserving the incoming rank within each
 * round.
 *
 * A capped list should answer "which files take untrusted input?" before it
 * answers "how many times does this one file take it?". Ranked alone, a single
 * server module with forty `req.` reads consumed most of the budget while forty
 * separate route files, each with one, got nothing — so the cap decided breadth
 * by accident. This makes N slots cover up to N distinct files.
 */
function breadthFirstByFile(ranked: EntryPoint[]): EntryPoint[] {
  const rounds = new Map<string, EntryPoint[]>();
  for (const e of ranked) (rounds.get(e.file) ?? rounds.set(e.file, []).get(e.file)!).push(e);
  const out: EntryPoint[] = [];
  for (let i = 0; out.length < ranked.length; i++) {
    let anyThisRound = false;
    for (const list of rounds.values()) {
      const at = list[i];
      if (at) {
        out.push(at);
        anyThisRound = true;
      }
    }
    if (!anyThisRound) break; // total: every file exhausted
  }
  return out;
}

/** Build the attack-surface map. `coveredScopes` marks targets a prior run handled. */
export function buildAttackSurface(scan: RepoScan, coveredScopes: string[] = []): AttackSurface {
  const covered = new Set(coveredScopes);
  const entryByKind = new Map<string, EntryPoint[]>();
  const sinkByKind = new Map<string, SinkSummary>();
  const langAgg = new Map<string, LangSummary>();
  const dirAgg = new Map<string, DirSummary>();
  const fileAgg: FileSurface[] = [];
  const regionOf = regionKeyer(scan.repo);
  let totalSources = 0;
  let totalSinks = 0;

  for (const f of scan.files) {
    const lang = langForFile(f.rel);
    if (!lang) continue;
    const dir = regionOf(f.rel);
    const la = langAgg.get(f.lang) ?? langAgg.set(f.lang, { lang: f.lang, files: 0, sources: 0, sinks: 0 }).get(f.lang)!;
    const da = dirAgg.get(dir) ?? dirAgg.set(dir, { dir, files: 0, sources: 0, sinks: 0, score: 0 }).get(dir)!;
    la.files++;
    da.files++;
    const fs: FileSurface = { file: f.rel, region: dir, sources: 0, sinks: 0, score: 0 };

    const text = readText(join(scan.repo, f.rel));
    const sources = findSources(lang, text, f.rel);
    for (const s of sources) {
      totalSources++;
      la.sources++;
      da.sources++;
      const w = entryWeight(s.kind);
      da.score += w;
      fs.sources++;
      fs.score += w;
      const arr = entryByKind.get(s.kind) ?? entryByKind.set(s.kind, []).get(s.kind)!;
      arr.push({ file: f.rel, line: s.line, kind: s.kind, title: s.title });
    }

    for (const sink of findSinks(lang, f.calls, undefined, f.imports, localDefNames(f.symbols), text.split(/\r?\n/))) {
      totalSinks++;
      la.sinks++;
      da.sinks++;
      da.score += SEV_WEIGHT[sink.severity];
      fs.sinks++;
      fs.score += SEV_WEIGHT[sink.severity];
      const ss =
        sinkByKind.get(sink.kind) ??
        sinkByKind.set(sink.kind, { kind: sink.kind, cwe: sink.cwe, severity: sink.severity, count: 0, samples: [] }).get(sink.kind)!;
      ss.count++;
      if (ss.samples.length < MAX_SAMPLES) ss.samples.push({ file: f.rel, line: sink.line, callee: sink.callee });
    }

    if (fs.score > 0) fileAgg.push(fs);
  }

  // Selected by RANK, presented by path. Sorting by filename and slicing made
  // every sample list an alphabetical PREFIX: on a monorepo whose web app lives
  // under `targets/`, its routes fell off the end of every list downstream —
  // and detecting MORE of them made it worse, because the extra hits pushed the
  // cap further up the alphabet.
  const fileScore = new Map(fileAgg.map((f) => [f.file, f.score]));
  const bySurfaceThenPath = (a: EntryPoint, b: EntryPoint) =>
    (fileScore.get(b.file) ?? 0) - (fileScore.get(a.file) ?? 0) || byStr(a.file, b.file) || a.line - b.line;
  const entryPoints: EntryGroup[] = [...entryByKind.entries()]
    .sort((a, b) => byStr(a[0], b[0]))
    .map(([kind, eps]) => {
      const kept = breadthFirstByFile(eps.sort(bySurfaceThenPath)).slice(0, MAX_ENTRY_SAMPLES);
      return { kind, count: eps.length, samples: kept.sort((a, b) => byStr(a.file, b.file) || a.line - b.line) };
    });

  const sinks = [...sinkByKind.values()].sort(
    (a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || b.count - a.count || byStr(a.kind, b.kind),
  );
  for (const s of sinks) s.samples.sort((a, b) => byStr(a.file, b.file) || a.line - b.line);

  const byLanguage = [...langAgg.values()].sort((a, b) => byStr(a.lang, b.lang));
  const byTopDir = [...dirAgg.values()].sort((a, b) => b.score - a.score || b.sinks - a.sinks || byStr(a.dir, b.dir));
  // Ranked, not sampled, and not alphabetical — this is what anything CHOOSING
  // files must read. Ties break on the path so the order stays deterministic.
  const byFile = fileAgg.sort((a, b) => b.score - a.score || b.sinks - a.sinks || byStr(a.file, b.file));

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
    byFile,
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
    const shown = g.samples.slice(0, MAX_SAMPLES);
    L.push(`- **${g.kind}** (${g.count}): ${shown.map((e) => `\`${e.file}:${e.line}\``).join(", ")}${g.count > shown.length ? " …" : ""}`);
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
