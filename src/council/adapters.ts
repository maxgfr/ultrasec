import { accessSync, constants } from "node:fs";
import { delimiter, join } from "node:path";

// Per-CLI adapters for `council`: how each external agent CLI is started on a
// snapshot, how one of its sessions is resumed for a single closing turn, and
// which output format it speaks.
//
// Every quirk below was paid for on a real audit that ran three of these CLIs in
// parallel as blind reviewers. They are argv arrays, never shell strings, and
// the message is always the SHORT static pointer to the brief file — a ~60 KB
// prompt passed as one argv element made opencode hang at init for eleven
// minutes, and the brief carries attacker-influenced code paths that must never
// reach a command line anyway (the same rule powered mode follows).

export type CouncilCli = "opencode" | "kilo" | "vibe" | "claude" | "codex";
export const COUNCIL_CLIS: readonly CouncilCli[] = ["opencode", "kilo", "vibe", "claude", "codex"];

/** What the CLI prints on stdout. */
export type EventFormat = "opencode-json" | "claude-json" | "text";

export interface InvocationInput {
  model: string;
  /** The snapshot directory the reviewer works in. */
  dir: string;
  /** The short argv message (never the brief itself). */
  message: string;
  /** Session title, for the CLIs that take one. */
  title: string;
  /** Session to resume, for `resume`. */
  session?: string;
  maxTurns: number;
}

export interface CouncilAdapter {
  cli: CouncilCli;
  /** Binary looked up on PATH. */
  bin: string;
  format: EventFormat;
  /** Whether token/cost usage can be read from the output at all. */
  usageExposed: boolean;
  /** Arguments (after the binary) for a fresh review. */
  start(i: InvocationInput): string[];
  /** Arguments to resume `i.session` for ONE more turn, or null when the CLI
   *  cannot resume a session it did not tell us the id of. */
  resume(i: InvocationInput): string[] | null;
  /** Extra environment for this CLI — configuration only, never a credential. */
  env?(model: string): Record<string, string>;
}

/** kilo addresses its own gateway as `kilo/<provider>/<model>`; accept both spellings. */
export function kiloModel(model: string): string {
  return model.startsWith("kilo/") ? model : `kilo/${model}`;
}

export const ADAPTERS: Record<CouncilCli, CouncilAdapter> = {
  // `--pure` is not optional. A user plugin (oh-my-opencode's "Sisyphus")
  // replaced the default agent and delegated to a model that did not exist; the
  // run stalled with no error. `plan` is the read-only primary agent, and it is
  // only reachable with external plugins switched off.
  opencode: {
    cli: "opencode",
    bin: "opencode",
    format: "opencode-json",
    usageExposed: true,
    start: (i) => ["run", "-m", i.model, "--agent", "plan", "--pure", "--dir", i.dir, "--format", "json", "--title", i.title, i.message],
    resume: (i) =>
      i.session
        ? ["run", "-s", i.session, "-m", i.model, "--agent", "plan", "--pure", "--dir", i.dir, "--format", "json", "--title", i.title, i.message]
        : null,
  },
  // kilo is an opencode fork: same events, same `-s` resume. `--auto` is what
  // keeps a headless run from blocking on a permission prompt; with `--agent
  // plan` it approves only what that agent does not explicitly deny (edits are
  // denied). The snapshot is a disposable copy and the environment is emptied,
  // which is what contains the rest.
  kilo: {
    cli: "kilo",
    bin: "kilo",
    format: "opencode-json",
    usageExposed: true,
    start: (i) => ["run", "-m", kiloModel(i.model), "--agent", "plan", "--pure", "--auto", "--dir", i.dir, "--format", "json", "--title", i.title, i.message],
    resume: (i) =>
      i.session
        ? [
            "run",
            "-s",
            i.session,
            "-m",
            kiloModel(i.model),
            "--agent",
            "plan",
            "--pure",
            "--auto",
            "--dir",
            i.dir,
            "--format",
            "json",
            "--title",
            i.title,
            i.message,
          ]
        : null,
  },
  // vibe prints its text only when the run ends — there is nothing to watch
  // mid-run, and no usage. Its model is configuration (`active_model`), so it
  // goes through the environment. `--max-price` exists but was never observed
  // stopping a run; the budget here is the turn cap and our own timeout.
  vibe: {
    cli: "vibe",
    bin: "vibe",
    format: "text",
    usageExposed: false,
    start: (i) => ["-p", i.message, "--agent", "plan", "--trust", "--workdir", i.dir, "--max-turns", String(i.maxTurns), "--output", "text"],
    resume: (i) =>
      i.session
        ? [
            "--resume",
            i.session,
            "-p",
            i.message,
            "--agent",
            "plan",
            "--trust",
            "--workdir",
            i.dir,
            "--max-turns",
            "1",
            "--disabled-tools",
            "re:.*",
            "--output",
            "text",
          ]
        : null,
    env: (model): Record<string, string> => (model ? { VIBE_ACTIVE_MODEL: model } : {}),
  },
  claude: {
    cli: "claude",
    bin: "claude",
    format: "claude-json",
    usageExposed: true,
    start: (i) => [
      "-p",
      i.message,
      "--output-format",
      "json",
      "--allowedTools",
      "Read,Grep,Glob",
      "--max-turns",
      String(i.maxTurns),
      ...(i.model ? ["--model", i.model] : []),
    ],
    resume: (i) =>
      i.session
        ? [
            "-p",
            i.message,
            "--resume",
            i.session,
            "--output-format",
            "json",
            "--allowedTools",
            "Read,Grep,Glob",
            "--max-turns",
            "1",
            ...(i.model ? ["--model", i.model] : []),
          ]
        : null,
  },
  // The snapshot is not a git checkout, which codex refuses without
  // `--skip-git-repo-check`. Its text output names no session, so no resume.
  codex: {
    cli: "codex",
    bin: "codex",
    format: "text",
    usageExposed: false,
    start: (i) => ["exec", "--sandbox", "read-only", "--skip-git-repo-check", "-C", i.dir, ...(i.model ? ["-m", i.model] : []), i.message],
    resume: () => null,
  },
};

export function isCouncilCli(s: string): s is CouncilCli {
  return (COUNCIL_CLIS as readonly string[]).includes(s);
}

export interface ModelSpec {
  cli: CouncilCli;
  model: string;
}

/**
 * Parse `cli:model[,cli:model…]`. The split is on the FIRST colon only: kilo's
 * free models are spelled `…:free`. Fail-closed on an unknown CLI — a typo that
 * silently dropped a reviewer would read as "that model found nothing".
 */
export function parseModelList(raw: string, flag: string): ModelSpec[] {
  const out: ModelSpec[] = [];
  for (const part of raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)) {
    const at = part.indexOf(":");
    const cli = at < 0 ? part : part.slice(0, at);
    const model = at < 0 ? "" : part.slice(at + 1).trim();
    if (!isCouncilCli(cli)) throw new Error(`${flag}: unknown CLI "${cli}" in "${part}" (known: ${COUNCIL_CLIS.join(", ")})`);
    out.push({ cli, model });
  }
  if (!out.length) throw new Error(`${flag}: no cli:model entry`);
  return out;
}

export interface Reviewer extends ModelSpec {
  /** Stable name: the CLI, suffixed `-2`, `-3` when the same CLI appears twice. */
  name: string;
  focus?: string;
}

/** Name each model spec, and attach its `--focus` area. */
export function reviewersFrom(specs: ModelSpec[], focus: Record<string, string> = {}): Reviewer[] {
  const seen = new Map<string, number>();
  return specs.map((s) => {
    const n = (seen.get(s.cli) ?? 0) + 1;
    seen.set(s.cli, n);
    const name = n === 1 ? s.cli : `${s.cli}-${n}`;
    const f = Object.hasOwn(focus, name) ? focus[name] : undefined;
    return { ...s, name, ...(f ? { focus: f } : {}) };
  });
}

/** `--focus "kilo=targets/frontend;opencode=targets/hasura"` → by reviewer name. */
export function parseFocus(raw: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!raw) return out;
  for (const part of raw.split(";")) {
    const eq = part.indexOf("=");
    if (eq <= 0) continue;
    const name = part.slice(0, eq).trim();
    const area = part.slice(eq + 1).trim();
    if (name && area) out[name] = area;
  }
  return out;
}

/**
 * Is `bin` an executable on PATH? A filesystem probe, NOT a spawn: `council`
 * without `--models` promises to call nothing, and `--version` on some of these
 * CLIs phones home for an upgrade check.
 */
export function onPath(bin: string, path = process.env.PATH ?? ""): string | undefined {
  const exts = process.platform === "win32" ? ["", ".exe", ".cmd"] : [""];
  for (const dir of path.split(delimiter).filter(Boolean)) {
    for (const ext of exts) {
      const p = join(dir, bin + ext);
      try {
        accessSync(p, constants.X_OK);
        return p;
      } catch {
        /* not here */
      }
    }
  }
  return undefined;
}
