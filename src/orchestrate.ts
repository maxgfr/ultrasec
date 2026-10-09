import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import type { InvestigateRegion } from "./investigate.js";
import { agentContracts, phaseWorkflowScript, runbookMd } from "./orchestrate-templates.js";
import type { RevalidateItem } from "./revalidate.js";
import { ADJUDICATION_SURFACE, inSurface, type SurfaceFilter } from "./surface.js";
import type { Finding } from "./types.js";
import { verifyItemOf, type VerifyItem } from "./verify.js";
import { workPath } from "./runlayout.js";
import { adjudicationFamilies } from "./family.js";
import { compactContextDoc, loadContextDoc } from "./context.js";

// ---------------------------------------------------------------------------
// `ultrasec orchestrate` — emit the run's multi-agent orchestration from its
// CURRENT worklists (per-phase workflow scripts + dispatch contracts + a
// sequential RUNBOOK), so a subagent-capable harness fans the judgment work
// out while the main agent stays the sole writer. Per-phase emission is
// deliberate: each worklist only exists after its engine step (`scan`,
// `verify --run`, `revalidate --run`, `investigate --run`), so a
// whole-pipeline script could only carry placeholders — exactly what the
// grounding/`check` gates exist to prevent.
//
// Verify fan-out note: `verify --shards N --shard i` exists, but each shard
// invocation WRITES a `VERIFY.todo.<i>.json` into the run dir and re-derives
// its slice from findings.json at call time — a write, and a drift risk if the
// dossier moves between emit and dispatch. So orchestrate batches the ids of
// the ONE emitted `VERIFY.todo.json` instead (baked in at emit time):
// subagents stay read-only and the worklist stays the source of truth.
//
// Batching is by FAMILY, under a ceiling on agents. Fixed batches of 8 sent 62
// agents at 494 code candidates on a real monorepo, each re-reading CONTEXT.md
// and re-opening the worklist; most batches held members of the same few
// families, decided eight times over. A family now travels whole to one agent,
// which reads its first member in depth and the rest for their location, and
// the batch size grows with the worklist so the agent count never passes
// MAX_AGENTS. The items themselves are baked into the prompt as compact JSON
// lines — no agent opens a shared worklist.
// ---------------------------------------------------------------------------

export const PHASES = ["adjudicate", "verify", "revalidate", "investigate"] as const;
export type PhaseName = (typeof PHASES)[number];

/** Small worklists don't amortize a fan-out — orchestrate says so and nudges --eco. */
export const SMALL_WORKLIST = 3;
/** The floor of a batch: below MAX_AGENTS × BATCH_SIZE items, one agent per
 *  BATCH_SIZE items, as before. */
export const BATCH_SIZE = 8;
/** The ceiling on agents per phase. Past it the batches grow instead. */
export const MAX_AGENTS = 12;

/**
 * Pack whole groups (families) into at most `maxAgents` batches — each batch
 * a list of its groups, so the prompt can still say where a family starts.
 *
 * The batch count is what fixed batches of `minBatch` would give, capped at
 * `maxAgents`; groups are then placed largest first into the lightest batch
 * (ties: the earlier group, the earlier batch), so the load stays balanced and
 * no group is ever split. Within a batch, groups keep their input order, and
 * batches are ordered by their first group — deterministic for a given input.
 */
export function packFamilies(groups: readonly string[][], maxAgents = MAX_AGENTS, minBatch = BATCH_SIZE): string[][][] {
  const live = groups.map((g, i) => ({ g, i })).filter((x) => x.g.length > 0);
  const total = live.reduce((n, x) => n + x.g.length, 0);
  if (!total) return [];
  const k = Math.max(1, Math.min(maxAgents, Math.ceil(total / minBatch), live.length));
  const bins = Array.from({ length: k }, () => ({ load: 0, members: [] as { g: string[]; i: number }[] }));
  const bySize = live.slice().sort((a, b) => b.g.length - a.g.length || a.i - b.i);
  for (const x of bySize) {
    let best = bins[0]!;
    for (const b of bins) if (b.load < best.load) best = b;
    best.load += x.g.length;
    best.members.push(x);
  }
  return bins
    .filter((b) => b.members.length)
    .map((b) => b.members.sort((a, c) => a.i - c.i))
    .sort((a, b) => a[0]!.i - b[0]!.i)
    .map((m) => m.map((x) => x.g));
}

export interface PhaseInfo {
  name: PhaseName;
  ready: boolean;
  /** Absolute path of the worklist this phase fans out over. */
  worklist: string;
  items: number;
  /** The injected fan-out ids (finding `id`s; `region` names for investigate). */
  ids: string[];
  /** The engine command that produces the worklist when it is missing. */
  prerequisite: string;
}

/** Read a JSON-array worklist, mapping each entry to its fan-out id (null = not ready). */
function readIds<T>(path: string, id: (item: T) => string): string[] | null {
  if (!existsSync(path)) return null;
  try {
    const items = JSON.parse(readFileSync(path, "utf8")) as T[];
    if (!Array.isArray(items)) return null;
    return items.map((i) => String(id(i)));
  } catch {
    return null; // unreadable worklist = not ready
  }
}

// Re-exported: the commands that take `--surface` imported it from here first.
export { SURFACE_FILTERS, type SurfaceFilter } from "./surface.js";

export function listPhases(runDir: string, engineAbs: string, surface: SurfaceFilter = ADJUDICATION_SURFACE): PhaseInfo[] {
  const run = resolve(runDir);

  // adjudicate fans out over the dossier's OPEN candidates — the scan's
  // recall-oriented candidate list itself (ids as accepted by `dossier <id>`).
  //
  // `--surface code` narrows it, and the narrowing is the difference between a
  // usable fan-out and an absurd one: on a real monorepo the open tier was 882
  // candidates — 111 subagents at 8 per batch — of which 190 were dependency
  // advisories that a `dossier` read cannot help with. Those are triaged from a
  // ranked list, not read one by one — so the default is `code+supply`, and
  // `--surface all` restores the old scope.
  const findingsPath = join(run, "findings.json");
  const allIds = readIds<Finding>(findingsPath, (f) => f.id);
  let adjIds: string[] = [];
  const byId = new Map<string, Finding>();
  if (allIds !== null) {
    try {
      const findings = JSON.parse(readFileSync(findingsPath, "utf8")) as Finding[];
      for (const f of findings) byId.set(f.id, f);
      adjIds = findings.filter((f) => f.status === "open" && inSurface(f, surface)).map((f) => f.id);
    } catch {
      /* readIds already vetted the file; keep [] on a racing rewrite */
    }
  }
  // The verify and revalidate phases fan out over their worklists, which their
  // own `--surface` already scoped. An older worklist emitted with every
  // advisory in it is narrowed here the same way; an id the dossier does not
  // know is kept, so the contract's "skip it and say so" still applies.
  const scoped = (ids: string[] | null): string[] | null =>
    ids === null || surface === "all" ? ids : ids.filter((id) => !byId.has(id) || inSurface(byId.get(id)!, surface));

  const verPath = join(run, "VERIFY.todo.json");
  const verIds = scoped(readIds<VerifyItem>(verPath, (i) => i.id));

  const revPath = join(run, "REVALIDATE.todo.json");
  const revIds = scoped(readIds<RevalidateItem>(revPath, (i) => i.id));

  const invPath = join(run, "INVESTIGATE.todo.json");
  const invIds = readIds<InvestigateRegion>(invPath, (r) => r.region);

  return [
    {
      name: "adjudicate",
      ready: allIds !== null,
      worklist: findingsPath,
      items: adjIds.length,
      ids: adjIds,
      // The manifest knows the audited repo once a scan ran; placeholder pre-scan.
      prerequisite: `node ${engineAbs} scan --repo ${repoOf(run)} --out ${run}`,
    },
    {
      name: "verify",
      ready: verIds !== null,
      worklist: verPath,
      items: verIds?.length ?? 0,
      ids: verIds ?? [],
      prerequisite: `node ${engineAbs} verify --run ${run}`,
    },
    {
      name: "revalidate",
      ready: revIds !== null,
      worklist: revPath,
      items: revIds?.length ?? 0,
      ids: revIds ?? [],
      prerequisite: `node ${engineAbs} revalidate --run ${run}`,
    },
    {
      name: "investigate",
      ready: invIds !== null,
      worklist: invPath,
      items: invIds?.length ?? 0,
      ids: invIds ?? [],
      prerequisite: `node ${engineAbs} investigate --run ${run}`,
    },
  ];
}

/** What one phase's workflow carries: its batches, families kept whole, and
 *  the compact JSON line each item is handed to its agent as. */
export interface BatchPlan {
  batches: string[][][];
  lines: Record<string, string>;
}

/** Fields a worklist row carries EMPTY for the adjudicator to fill. Not
 *  evidence, so a prompt line leaves them out; a filled one is kept. */
const ANSWER_FIELDS = new Set(["verdict", "note", "brocard", "fixedIn"]);

/** One item as the single JSON line its agent reads. */
export function compactLine(item: object): string {
  return JSON.stringify(item, (k, v) => (ANSWER_FIELDS.has(k) && (v === null || v === "") ? undefined : v));
}

function readArray<T>(path: string): T[] {
  try {
    const v = JSON.parse(readFileSync(path, "utf8")) as unknown;
    return Array.isArray(v) ? (v as T[]) : [];
  } catch {
    return [];
  }
}

/**
 * The batch plan of a ready phase: the items as compact lines, the finding
 * phases grouped into families (`adjudicationKey`), packed under MAX_AGENTS.
 * An item the source no longer holds still gets a line — its bare id — so the
 * agent's "skip it and say so" applies rather than a silent drop.
 */
export function planPhase(ph: PhaseInfo, findingsById: ReadonlyMap<string, Finding>): BatchPlan {
  const lines: Record<string, string> = {};
  let groups: string[][];
  if (ph.name === "investigate") {
    const regions = new Map(readArray<InvestigateRegion>(ph.worklist).map((r) => [String(r.region), r]));
    for (const id of ph.ids) lines[id] = compactLine(regions.get(id) ?? { region: id });
    groups = ph.ids.map((id) => [id]);
  } else {
    const rows = ph.name === "adjudicate" ? new Map<string, object>() : new Map(readArray<{ id: string }>(ph.worklist).map((r) => [String(r.id), r as object]));
    for (const id of ph.ids) {
      const f = findingsById.get(id);
      const row = ph.name === "adjudicate" ? (f ? verifyItemOf(f) : undefined) : rows.get(id);
      lines[id] = compactLine(row ?? { id });
    }
    groups = adjudicationFamilies(ph.ids, (id) => findingsById.get(id));
  }
  return { batches: packFamilies(groups), lines };
}

export interface OrchestrateOptions {
  /** Emit only this phase (exit 2 if its worklist does not exist yet). */
  phase?: string;
  /** Emit only the RUNBOOK + contracts (the explicit low-token sequential path). */
  eco?: boolean;
  /** Narrow the fan-out to a surface. Default `code+supply`. */
  surface?: SurfaceFilter;
}

export interface OrchestrateResult {
  exitCode: number;
  written: string[];
  notices: string[];
  errors: string[];
  phases: PhaseInfo[];
}

/** The audited repo root, as the run's manifest recorded it (placeholder pre-scan). */
function repoOf(run: string): string {
  try {
    const m = JSON.parse(readFileSync(join(run, "manifest.json"), "utf8")) as { repo?: string };
    if (typeof m.repo === "string" && m.repo) return m.repo;
  } catch {
    /* no manifest yet — the runbook keeps the placeholder */
  }
  return "<repo>";
}

export function orchestrateRun(runDir: string, engineAbs: string, opts: OrchestrateOptions = {}): OrchestrateResult {
  const run = resolve(runDir);
  if (!existsSync(run)) {
    return { exitCode: 2, written: [], notices: [], errors: [`run dir not found: ${run}`], phases: [] };
  }
  const phases = listPhases(run, engineAbs, opts.surface ?? ADJUDICATION_SURFACE);

  let selected = phases.filter((p) => p.ready);
  if (opts.phase !== undefined) {
    const ph = phases.find((p) => p.name === opts.phase);
    if (!ph) {
      return {
        exitCode: 2,
        written: [],
        notices: [],
        errors: [`unknown phase "${opts.phase}" — expected one of: ${PHASES.join(", ")}.`],
        phases,
      };
    }
    if (!ph.ready) {
      return {
        exitCode: 2,
        written: [],
        notices: [],
        errors: [`phase "${ph.name}" is not ready — its worklist ${ph.worklist} does not exist yet. Produce it first: ${ph.prerequisite}`],
        phases,
      };
    }
    selected = [ph];
  }

  const repoAbs = repoOf(run);
  const orchDir = workPath(run, "orchestration");
  const agentsDir = join(orchDir, "agents");
  // One fragment dir per phase: `verify --apply` serves both adjudicate and
  // verify, so fragments must not share a flat out/ a directory apply could
  // cross-pick from. The runbook cites every phase's path — create them all.
  for (const p of PHASES) mkdirSync(join(orchDir, "out", p), { recursive: true });
  mkdirSync(agentsDir, { recursive: true });

  const written: string[] = [];
  const notices: string[] = [];

  // Contracts: every role, every call (idempotent overwrite) — they double as the
  // RUNBOOK's self-pass checklists, so eco mode needs them too.
  for (const [name, content] of Object.entries(agentContracts(run, engineAbs, repoAbs))) {
    const p = join(agentsDir, `${name}.md`);
    writeFileSync(p, content);
    written.push(p);
  }

  // CONTEXT.md once per agent, compacted to what bears on a verdict — not once
  // per `dossier` call, which is what eight reprints per agent used to cost.
  const doc = loadContextDoc(run);
  const context = doc ? (compactContextDoc(doc) ?? doc) : undefined;
  const findingsById = new Map(readArray<Finding>(join(run, "findings.json")).map((f) => [f.id, f]));

  if (!opts.eco) {
    for (const ph of selected) {
      if (ph.items === 0) {
        notices.push(`phase "${ph.name}": worklist is empty — nothing to orchestrate.`);
        continue;
      }
      if (ph.items <= SMALL_WORKLIST) {
        notices.push(`phase "${ph.name}": only ${ph.items} item(s) — the sequential --eco path is equivalent and cheaper.`);
      }
      const p = join(orchDir, `${ph.name}.workflow.mjs`);
      writeFileSync(p, phaseWorkflowScript(ph, run, engineAbs, BATCH_SIZE, { plan: planPhase(ph, findingsById), context }));
      written.push(p);
    }
  }

  const rb = join(orchDir, "RUNBOOK.md");
  writeFileSync(rb, runbookMd(phases, run, engineAbs, repoAbs));
  written.push(rb);

  return { exitCode: 0, written, notices, errors: [], phases };
}
