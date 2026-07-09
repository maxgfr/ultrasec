import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import type { InvestigateRegion } from "./investigate.js";
import { agentContracts, phaseWorkflowScript, runbookMd } from "./orchestrate-templates.js";
import type { RevalidateItem } from "./revalidate.js";
import type { Finding } from "./types.js";
import type { VerifyItem } from "./verify.js";

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
// the ONE emitted `VERIFY.todo.json` instead (8 per agent, baked in at emit
// time): subagents stay read-only and the worklist stays the source of truth.
// ---------------------------------------------------------------------------

export const PHASES = ["adjudicate", "verify", "revalidate", "investigate"] as const;
export type PhaseName = (typeof PHASES)[number];

/** Small worklists don't amortize a fan-out — orchestrate says so and nudges --eco. */
export const SMALL_WORKLIST = 3;
/** One subagent per batch of at most this many worklist items. */
export const BATCH_SIZE = 8;

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

export function listPhases(runDir: string, engineAbs: string): PhaseInfo[] {
  const run = resolve(runDir);

  // adjudicate fans out over the dossier's OPEN candidates — the scan's
  // recall-oriented candidate list itself (ids as accepted by `dossier <id>`).
  const findingsPath = join(run, "findings.json");
  const allIds = readIds<Finding>(findingsPath, (f) => f.id);
  let adjIds: string[] = [];
  if (allIds !== null) {
    try {
      const findings = JSON.parse(readFileSync(findingsPath, "utf8")) as Finding[];
      adjIds = findings.filter((f) => f.status === "open").map((f) => f.id);
    } catch {
      /* readIds already vetted the file; keep [] on a racing rewrite */
    }
  }

  const verPath = join(run, "VERIFY.todo.json");
  const verIds = readIds<VerifyItem>(verPath, (i) => i.id);

  const revPath = join(run, "REVALIDATE.todo.json");
  const revIds = readIds<RevalidateItem>(revPath, (i) => i.id);

  const invPath = join(run, "INVESTIGATE.todo.json");
  const invIds = readIds<InvestigateRegion>(invPath, (r) => r.region);

  return [
    {
      name: "adjudicate",
      ready: allIds !== null,
      worklist: findingsPath,
      items: adjIds.length,
      ids: adjIds,
      prerequisite: `node ${engineAbs} scan --repo <repo> --out ${run}`,
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

export interface OrchestrateOptions {
  /** Emit only this phase (exit 2 if its worklist does not exist yet). */
  phase?: string;
  /** Emit only the RUNBOOK + contracts (the explicit low-token sequential path). */
  eco?: boolean;
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
  const phases = listPhases(run, engineAbs);

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
  const orchDir = join(run, "orchestration");
  const agentsDir = join(orchDir, "agents");
  mkdirSync(join(orchDir, "out"), { recursive: true });
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
      writeFileSync(p, phaseWorkflowScript(ph, run, engineAbs, BATCH_SIZE));
      written.push(p);
    }
  }

  const rb = join(orchDir, "RUNBOOK.md");
  writeFileSync(rb, runbookMd(phases, run, engineAbs, repoAbs));
  written.push(rb);

  return { exitCode: 0, written, notices, errors: [], phases };
}
