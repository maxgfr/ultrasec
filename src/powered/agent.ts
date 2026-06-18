import { spawnSync } from "node:child_process";
import { existsSync, statSync } from "node:fs";

// Powered mode's thin automation layer (Phase 7). ultrasec holds NO keys — they
// live in the user's own agent CLI (claude/codex/…). This runner invokes that CLI
// to FILL a worklist the deterministic engine emitted, then the pipeline applies
// the result through the SAME conservative apply functions as the manual path.
//
// Security: the CLI is invoked with an **argv array, never a shell string**, so a
// branch/file name can't inject a command. The worklist (which contains
// attacker-influenceable code excerpts) is passed as a FILE PATH the agent reads —
// its CONTENT is never interpolated into the command line. The instruction tells
// the agent to treat the cited code as untrusted DATA, not instructions, and we
// recommend sandboxing the external agent (see references/powered-mode.md).

export interface ArgvTemplate {
  name: string;
  /** Build the argv array from the instruction + run dir. */
  argv: (instruction: string, run: string) => string[];
}

// Built-in headless invocations. The instruction is a SINGLE argv element (so its
// spaces/metacharacters are inert) referencing the worklist + output file PATHS.
const BUILTINS: Record<string, ArgvTemplate> = {
  claude: { name: "claude", argv: (p) => ["claude", "-p", p] },
  codex: { name: "codex", argv: (p) => ["codex", "exec", p] },
};

/**
 * Resolve a template name (built-in) or a generic argv template string where the
 * tokens `{prompt}` and `{run}` are substituted per-token. e.g.
 * `"mytool exec {prompt}"` → `["mytool","exec", instruction]`. Whitespace-split,
 * so each token is its own argv element — never a shell string.
 */
export function resolveTemplate(tpl: string): ArgvTemplate {
  if (Object.prototype.hasOwnProperty.call(BUILTINS, tpl)) return BUILTINS[tpl]!;
  const parts = tpl.trim().split(/\s+/).filter(Boolean);
  if (!parts.length) throw new Error("empty agent template");
  return {
    name: parts[0]!,
    argv: (instruction, run) => parts.map((t) => t.replace(/\{prompt\}/g, instruction).replace(/\{run\}/g, run)),
  };
}

export function buildAgentArgv(tpl: string, instruction: string, run: string): string[] {
  return resolveTemplate(tpl).argv(instruction, run);
}

export interface AgentTask {
  /** Stage name (e.g. "verify"), for logging. */
  stage: string;
  /** Run dir (also the agent's cwd). */
  run: string;
  /** Path to the worklist the agent must READ. */
  worklist: string;
  /** Path the agent must WRITE its output to. */
  outPath: string;
  /** Human-readable instruction (the prompt) — references the paths above. */
  instruction: string;
}

export interface FillResult {
  ok: boolean;
  stderr?: string;
}

/** A runner that drives an external agent CLI to fill a worklist. */
export interface AgentRunner {
  fill(task: AgentTask): FillResult;
}

export type SpawnFn = (cmd: string, args: string[], cwd: string) => { status: number | null; stderr: string };

const defaultSpawn: SpawnFn = (cmd, args, cwd) => {
  const r = spawnSync(cmd, args, { encoding: "utf8", cwd, stdio: ["ignore", "pipe", "pipe"], timeout: 1000 * 60 * 30 });
  if (r.error) return { status: null, stderr: String((r.error as Error).message) };
  return { status: typeof r.status === "number" ? r.status : null, stderr: r.stderr ?? "" };
};

function nonEmptyFile(p: string): boolean {
  try {
    return existsSync(p) && statSync(p).size > 0;
  } catch {
    return false;
  }
}

/** Drives a configured CLI (argv-only) and verifies it produced the output file. */
export class CliAgentRunner implements AgentRunner {
  constructor(
    private readonly template: string,
    private readonly spawn: SpawnFn = defaultSpawn,
  ) {}

  fill(task: AgentTask): FillResult {
    const argv = buildAgentArgv(this.template, task.instruction, task.run);
    const [cmd, ...args] = argv;
    if (!cmd) return { ok: false, stderr: "empty agent argv" };
    const r = this.spawn(cmd, args, task.run);
    if (r.status !== 0) return { ok: false, stderr: r.stderr || `${cmd} exited ${r.status}` };
    if (!nonEmptyFile(task.outPath)) return { ok: false, stderr: `agent did not write ${task.outPath}` };
    return { ok: true };
  }
}
