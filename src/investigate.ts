import type { Dossier } from "./store.js";
import type { Finding } from "./types.js";
import type { AttackSurface } from "./map.js";
import type { Graph } from "./graph.js";
import { neighbors } from "./neighbors.js";
import { makeToolFinding } from "./tools/normalize.js";
import { deploymentFacts, scoreFinding } from "./tools/scoring.js";
import { insideRepo, lineCount } from "./check.js";
import { byStr } from "./util.js";
import { leadsForRegion } from "./assumptions.js";
import {
  DISCOVERY_REQUIREMENT,
  coerceRows,
  parseDiscoveryRow,
  requireUsable,
  type DiscoveryRow,
  type DroppedRow,
  type NormalizedRow,
  type ParseResult,
} from "./apply-parse.js";

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
  /**
   * Unenforced assumptions recorded by `assumptions` that fall in this region.
   * A place where the code trusts something nothing verifies is the best hunting
   * lead an audit produces — it names the gap instead of asking you to find it.
   * Absent unless that stage has run.
   */
  leads?: string[];
}

/**
 * Extra hunting frames the caller can request. A lens does not change what is
 * scanned — it changes the question asked of it, which is the only thing that
 * separates "no findings" from "no findings of the kind I was looking for".
 */
// Access control is the highest-yield class an audit finds and the one taint can
// never enumerate — the engine can point at the routes, only a human decides the
// policy. Kept as one string, shared by the `access-control` name and its `idor`
// alias, so the two can never drift.
const ACCESS_CONTROL_LENS =
  "Access control — the highest-yield class, never enumerable by taint. For every route/handler in these files ask two questions. (1) Is there ANY authorization check before the object is read or written? A missing one is BFLA (broken function-level authz) — the classic shape is an admin/privileged action reachable by a normal role, or a method/version downgrade (GET→PUT, /v2→/v1) that skips the guard. (2) Does the check bind the CALLER to the SPECIFIC object in the request? Compare the guard to the object returned: an owner_id/tenant_id taken from the SESSION/token vs. an id taken from the URL/body/query. When they are not compared, an attacker swaps the id and reads another principal's data — IDOR/BOLA. Hunt horizontal escalation (user A reaching user B via a predictable/sequential/enumerable id), vertical escalation (a normal user reaching an admin object), and tenant-boundary crossing in multi-tenant code. Mass-assignment onto role/isAdmin/tenant/permissions is access control too — a body field that overwrites who you are. Cite resolvable [file:line] for the guard that is missing or the comparison that is absent. See references/access-control.md.";

export const LENSES: Record<string, string> = {
  "sharp-edges":
    "Ask a DIFFERENT question here: not 'is this code vulnerable' but 'does this API make the insecure use easier than the secure one'. Six shapes: an algorithm/mode the caller picks; an insecure default or an ambiguous zero; raw bytes where a semantic type belongs; a config cliff that fails open; a verification that returns instead of throwing; permissions as strings. Model three users — the attacker, the copy-paster, the confused reader. Rate by how EASY the mistake is. See references/sharp-edges.md.",
  "access-control": ACCESS_CONTROL_LENS,
  idor: ACCESS_CONTROL_LENS,
  crypto:
    "Crypto-specific: secrets compared with == or equals() rather than a constant-time helper; key material in a plain buffer never zeroed; a nonce or IV reused or derived from a counter the attacker sees; an algorithm read from attacker-supplied data. See references/attack-classes.md §Cryptography.",
  privacy:
    "Personal data: where it goes (a third-party processor, a log, an analytics beacon), how long it stays, and whether a control named 'anonymisation' actually prevents re-identification. See references/privacy-and-data-protection.md.",
  cloud:
    "Cloud / container reachability, the half the IaC scan can't decide: can any user-controlled URL reach the instance-metadata endpoint (169.254.169.254 / metadata.google.internal) — SSRF to short-lived credentials? Is a wildcard/over-broad IAM role actually assumed on this path? Are instance/CI secrets read from env or a mounted file that a compromised container can exfiltrate? Does a container escape (privileged/hostPath/hostNetwork) turn a bug into node takeover? See references/frameworks.md §Cloud.",
};

/** Build the investigation worklist, grouped by attack-surface region. */
export function buildInvestigateWorklist(
  surface: AttackSurface,
  graph: Graph,
  assumptionLeads: { at: string; claim: string }[] = [],
  lens?: string,
): InvestigateRegion[] {
  // `surface.byFile` is the FULL ranked set. The previous version read
  // `entryPoints[].samples` and `sinks[].samples` — each already capped at 8 per
  // kind — and then sorted the survivors alphabetically, so a region's file list
  // was a sample of a sample in name order. On a monorepo that put
  // `targets/alert-cli/**` in all 8 slots of the `targets` region and left
  // `targets/frontend/**`, the only internet-facing component, entirely out of
  // the worklist. Rank by attack surface, then cap.
  const filesByRegion = new Map<string, string[]>();
  for (const fs of surface.byFile) {
    const arr = filesByRegion.get(fs.region) ?? filesByRegion.set(fs.region, []).get(fs.region)!;
    if (arr.length < MAX_FILES_PER_REGION) arr.push(fs.file);
  }

  const regions: InvestigateRegion[] = [];
  for (const t of surface.suggestedTargets) {
    const files = [...(filesByRegion.get(t.scope) ?? [])];
    const nb = new Set<string>();
    for (const f of files) {
      if (!graph.files.includes(f)) continue;
      for (const l of neighbors(graph, f, 1).links) nb.add(l.node);
    }
    for (const f of files) nb.delete(f);
    const leads = leadsForRegion(assumptionLeads, t.scope, files);
    regions.push({
      region: t.scope,
      score: t.score,
      sinks: t.sinks,
      sources: t.sources,
      files,
      neighbors: [...nb].sort(byStr).slice(0, MAX_NEIGHBORS_PER_REGION),
      prompt:
        "What the deterministic pass can't see: missing/incorrect authorization & IDOR, " +
        "business-logic flaws, multi-hop taint that crosses these files, and personal-data " +
        "handling (data leaving to a third-party processor, a control narrower than its name, " +
        "reversible pseudonymisation, absent retention). Cite resolvable [file:line]." +
        (lens && LENSES[lens] ? `\n\nLENS — ${lens}: ${LENSES[lens]}` : ""),
      ...(leads.length ? { leads } : {}),
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
    if (r.leads?.length) {
      L.push(`- **trusted but never enforced here** (from \`assumptions\`) — start with these:`);
      for (const l of r.leads) L.push(`  - ${l}`);
    }
    L.push("");
  }
  return L.join("\n") + "\n";
}

/**
 * One agent-authored finding.
 *
 * Defined in `apply-parse.ts` beside the validator that enforces it, and
 * re-exported here because this is the stage that named it. `variants.ts`
 * imports it from here and gets the same shape — and, now, the same validation.
 */
export type Discovery = DiscoveryRow;

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

/**
 * `ident` is tolerated as possibly-absent on purpose. Every caller now passes a
 * validated row, but this function is one `??` away from a crash that took a
 * whole audit's report down once already (`variants --apply` handed it a row
 * with neither `cwe` nor `title`). A dedup key derived from an empty ident is a
 * worse key; it is not a stack trace.
 */
function dedupKey(category: string, ident: string | undefined, where: string): string {
  return `${category}::${(ident ?? "").trim().toLowerCase()}::${where}`;
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
 *
 * `opts.context` is the run's CONTEXT.md, and it is what makes an ingested
 * finding RANKABLE. Every renderer sorts on `risk`, `makeToolFinding` does not
 * set one, and nothing scored these findings afterwards — so agent discoveries
 * sorted below every scanner hit in the run, including the ones that had already
 * been refuted. They now get the same `severity ⊕ exposure ⊕ criticality` score
 * the scan gives everything else. Omitting the context is still valid: the score
 * then falls back to severity alone, which is what a run with no CONTEXT.md gets.
 */
export function ingestDiscoveries(dossier: Dossier, discoveries: Discovery[], repo: string, opts: { context?: string } = {}): IngestResult {
  const deployment = deploymentFacts(opts.context);
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
    f.risk = scoreFinding(f, deployment);
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
export function parseDiscoveries(raw: string): ParseResult<Discovery> {
  const arr = coerceRows(JSON.parse(raw) as unknown, ["discoveries"], "discoveries");
  const rows: Discovery[] = [];
  const dropped: DroppedRow[] = [];
  const normalized: NormalizedRow[] = [];
  const drop = (index: number, reason: string) => dropped.push({ index, reason });

  for (const [index, raw] of arr.entries()) {
    const parsed = parseDiscoveryRow(raw);
    if (!parsed.row) {
      drop(index, parsed.reason!);
      continue;
    }
    if (parsed.note) normalized.push({ index, note: parsed.note });
    rows.push(parsed.row);
  }

  return requireUsable(
    // Presence-gated: no fold ⇒ the result is shape-identical to before.
    { rows, dropped, ...(normalized.length ? { normalized } : {}) },
    arr.length,
    DISCOVERY_REQUIREMENT,
  );
}
