import type { Dossier } from "./store.js";
import { CATEGORIES, SEVERITIES, type Category, type Finding, type Severity } from "./types.js";
import type { AttackSurface } from "./map.js";
import type { Graph } from "./graph.js";
import { neighbors } from "./neighbors.js";
import { makeToolFinding } from "./tools/normalize.js";
import { insideRepo, lineCount } from "./check.js";
import { byStr } from "./util.js";

// The agentic-discovery stage (Phase 5). The deterministic engine can't enumerate
// authorization/IDOR, business-logic, or subtle multi-hop flows — so it emits a
// worklist organized by attack-surface REGION (entry/sink files + their 1-hop
// graph neighbours) and the agent investigates each region and returns grounded
// Discovery[]. The engine INGESTS them as `ultrasec-ai` candidates that flow
// through the same dossier → verify → check pipeline as any other finding. Two
// safety rails: a discovery duplicating an existing location folds into `sources`
// (not a new finding), and a citation that doesn't resolve is REJECTED up front —
// so `check` can never later fail on an AI-invented line.

const MAX_FILES_PER_REGION = 8;
const MAX_NEIGHBORS_PER_REGION = 12;
export const AI_TOOL = "ultrasec-ai";

function topDir(rel: string): string {
  const i = rel.indexOf("/");
  return i === -1 ? "." : rel.slice(0, i);
}

export interface InvestigateRegion {
  region: string;
  score: number;
  sinks: number;
  sources: number;
  /** Representative entry/sink files in this region. */
  files: string[];
  /** 1-hop graph neighbours of those files (cross-file context). */
  neighbors: string[];
  /** What to hunt for here — the things the deterministic pass can't. */
  prompt: string;
}

/** Build the investigation worklist, grouped by attack-surface region. */
export function buildInvestigateWorklist(surface: AttackSurface, graph: Graph): InvestigateRegion[] {
  const filesByRegion = new Map<string, Set<string>>();
  const add = (region: string, file: string) => (filesByRegion.get(region) ?? filesByRegion.set(region, new Set()).get(region)!).add(file);
  for (const g of surface.entryPoints) for (const s of g.samples) add(topDir(s.file), s.file);
  for (const k of surface.sinks) for (const s of k.samples) add(topDir(s.file), s.file);

  const regions: InvestigateRegion[] = [];
  for (const t of surface.suggestedTargets) {
    const files = [...(filesByRegion.get(t.scope) ?? [])].sort(byStr).slice(0, MAX_FILES_PER_REGION);
    const nb = new Set<string>();
    for (const f of files) {
      if (!graph.files.includes(f)) continue;
      for (const l of neighbors(graph, f, 1).links) nb.add(l.node);
    }
    for (const f of files) nb.delete(f);
    regions.push({
      region: t.scope,
      score: t.score,
      sinks: t.sinks,
      sources: t.sources,
      files,
      neighbors: [...nb].sort(byStr).slice(0, MAX_NEIGHBORS_PER_REGION),
      prompt:
        "What the deterministic pass can't see: missing/incorrect authorization & IDOR, " +
        "business-logic flaws, and multi-hop taint that crosses these files. Cite resolvable [file:line].",
    });
  }
  return regions;
}

export function renderInvestigateMd(regions: InvestigateRegion[], context?: string): string {
  const L: string[] = [];
  L.push(`# ultrasec investigation worklist (${regions.length} region${regions.length === 1 ? "" : "s"})`);
  L.push("");
  L.push(`Investigate each region for issues the deterministic engine can't enumerate, and emit`);
  L.push(`grounded **Discovery[]** as INVESTIGATE.json (array of`);
  L.push(`{title, category, severity, cwe?, message, file, line, path?}). Then:`);
  L.push(`\`ultrasec investigate --apply INVESTIGATE.json --run <run>\`.`);
  L.push("");
  L.push(`> Every discovery is ingested as an \`${AI_TOOL}\` **open** candidate and must be verified`);
  L.push(`> like any other. Citations are checked: a [file:line] that doesn't resolve is **rejected**.`);
  L.push(`> A discovery at an existing finding's location folds into its \`sources\` (no duplicate).`);
  L.push("");
  if (context) {
    L.push(`## Project context`);
    L.push(`_From \`CONTEXT.md\`._`);
    L.push("");
    L.push(context);
    L.push("");
  }
  for (const r of regions) {
    L.push(`## \`${r.region}\` — ${r.sinks} sink(s), ${r.sources} entry point(s)`);
    if (r.files.length) L.push(`- files: ${r.files.map((f) => `\`${f}\``).join(", ")}`);
    if (r.neighbors.length) L.push(`- neighbours: ${r.neighbors.map((f) => `\`${f}\``).join(", ")}`);
    L.push(`- hunt: ${r.prompt}`);
    L.push("");
  }
  return L.join("\n") + "\n";
}

export interface Discovery {
  title: string;
  category: Category;
  severity: Severity;
  cwe?: string;
  message: string;
  file: string;
  line: number;
  path?: { file: string; line: number; why: string }[];
}

export interface IngestResult {
  findings: Finding[];
  ingested: number;
  folded: number;
  rejected: { discovery: Discovery; reason: string }[];
}

function locOf(f: Finding): string {
  if (f.sink) return `${f.sink.file}:${f.sink.line}`;
  const last = f.path?.[f.path.length - 1];
  if (last) return `${last.file}:${last.line}`;
  if (f.source) return `${f.source.file}:${f.source.line}`;
  return "";
}

function dedupKey(category: string, ident: string, where: string): string {
  return `${category}::${ident.trim().toLowerCase()}::${where}`;
}

/** Reject a discovery whose primary or any path citation doesn't resolve in the
 *  repo — the SAME check the grounding gate applies, so `check` can't fail later. */
function citationProblem(repo: string, d: Discovery): string | null {
  const locs = [{ file: d.file, line: d.line }, ...(d.path ?? []).map((p) => ({ file: p.file, line: p.line }))];
  for (const loc of locs) {
    if (!insideRepo(repo, loc.file)) return `citation outside repo: ${loc.file}`;
    const lc = lineCount(repo, loc.file);
    if (lc === null) return `file not found: ${loc.file}`;
    if (loc.line < 1 || loc.line > lc) return `line out of range: ${loc.file}:${loc.line} (file has ${lc} lines)`;
  }
  return null;
}

/**
 * Ingest agent discoveries as `ultrasec-ai` open candidates. Dedups against the
 * existing dossier by (category, cwe|title, file:line): a match folds `ultrasec-ai`
 * into that finding's `sources` instead of adding a duplicate. Out-of-range
 * citations are rejected before folding. Stable, content-derived ids.
 */
export function ingestDiscoveries(dossier: Dossier, discoveries: Discovery[], repo: string): IngestResult {
  const result = new Map<string, Finding>();
  const idByKey = new Map<string, string>();
  for (const f of dossier.findings) {
    result.set(f.id, f);
    idByKey.set(dedupKey(f.category, f.cwe ?? f.title, locOf(f)), f.id);
  }

  let ingested = 0,
    folded = 0;
  const rejected: IngestResult["rejected"] = [];

  for (const d of discoveries) {
    const problem = citationProblem(repo, d);
    if (problem) {
      rejected.push({ discovery: d, reason: problem });
      continue;
    }
    const key = dedupKey(d.category, d.cwe ?? d.title, `${d.file}:${d.line}`);
    const existingId = idByKey.get(key);
    if (existingId) {
      const prev = result.get(existingId)!;
      const sources = [...new Set([...(prev.sources ?? [prev.tool]), AI_TOOL])].sort(byStr);
      result.set(existingId, { ...prev, sources });
      folded++;
      continue;
    }
    const f = makeToolFinding({
      tool: AI_TOOL,
      category: d.category,
      ident: `${d.category}:${d.title}:${d.file}:${d.line}`,
      title: d.title,
      severity: d.severity,
      message: d.message,
      file: d.file,
      line: d.line,
      cwe: d.cwe,
      confidence: "low", // AI-discovered + unverified — recall-oriented, adjudicate it
    });
    if (d.path?.length) f.path = d.path.map((p) => ({ file: p.file, line: p.line, why: p.why }));
    result.set(f.id, f);
    idByKey.set(key, f.id);
    ingested++;
  }

  const findings = [...result.values()].sort((a, b) => byStr(a.id, b.id));
  return { findings, ingested, folded, rejected };
}

/**
 * Parse an INVESTIGATE.json body into validated Discovery[]. Row-tolerant (drops
 * entries missing required fields or with an unknown category/severity) but
 * FAIL-CLOSED on the container: an unrecognized shape, or rows that ALL get
 * dropped, throws instead of silently ingesting nothing. An empty
 * {discoveries:[]} stays valid — a hunter finding nothing is a real outcome.
 */
export function parseDiscoveries(raw: string): Discovery[] {
  const data = JSON.parse(raw) as unknown;
  const arr = Array.isArray(data) ? data : Array.isArray((data as any)?.discoveries) ? (data as any).discoveries : null;
  if (arr === null) throw new Error(`unrecognized discoveries shape — expected a JSON array or {"discoveries":[...]} (fail-closed)`);
  const out: Discovery[] = [];
  for (const d of arr as any[]) {
    if (!d || typeof d !== "object") continue;
    if (typeof d.title !== "string" || typeof d.message !== "string" || typeof d.file !== "string") continue;
    if (!Number.isInteger(d.line) || d.line < 1) continue;
    if (!(CATEGORIES as readonly string[]).includes(d.category)) continue;
    if (!(SEVERITIES as readonly string[]).includes(d.severity)) continue;
    const path = Array.isArray(d.path)
      ? d.path
          .filter((p: any) => p && typeof p.file === "string" && Number.isInteger(p.line) && p.line >= 1)
          .map((p: any) => ({ file: p.file, line: p.line, why: typeof p.why === "string" ? p.why : "" }))
      : undefined;
    out.push({
      title: d.title,
      category: d.category as Category,
      severity: d.severity as Severity,
      ...(typeof d.cwe === "string" ? { cwe: d.cwe } : {}),
      message: d.message,
      file: d.file,
      line: d.line,
      ...(path && path.length ? { path } : {}),
    });
  }
  if ((arr as any[]).length > 0 && out.length === 0) {
    throw new Error(
      `${(arr as any[]).length} row(s), none usable — each needs title/message/file (strings), line ≥ 1, a category among ${CATEGORIES.join("|")} and a severity among ${SEVERITIES.join("|")} (fail-closed)`,
    );
  }
  return out;
}
