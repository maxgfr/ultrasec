import { existsSync, readFileSync, realpathSync, statSync } from "node:fs";
import { isAbsolute, join, resolve, sep } from "node:path";
import { COMMAND_HANDLERS } from "../commands/registry.js";
import { captureOutput, isScannableDir, type ParsedArgs } from "../util.js";
import { warmGrammars } from "../vendor/codeindex-engine.mjs";
import { withRunLock } from "../run-lock.js";

// Where a tool name becomes work.
//
// Unlike its sibling servers, this one calls the COMMAND layer rather than the
// library beneath it. That is deliberate: ultrasec's twenty commands carry real
// orchestration — budget presets, diff expansion, scanner fan-out, merge
// semantics — and reimplementing that here would produce a second audit
// pipeline that drifts from the one people actually run. Calling the same
// handler the CLI calls means a tool result and a CLI run cannot disagree.
//
// Two things make that safe, and neither was true before this server existed:
//
//   1. No command calls process.exit. They return an exit code, which is a
//      value we can act on. (cli.ts's `main` is what exits, and we never call
//      it.)
//   2. Commands PRINT their results, and this server's stdout carries JSON-RPC
//      frames only. `captureOutput` scopes the output sink with
//      AsyncLocalStorage, so each call collects exactly its own output even
//      when two tool calls interleave.

export interface HandlerDefaults {
  defaultRun?: string;
  allowWrite?: boolean;
}

export class ToolError extends Error {}

export interface ToolOutcome {
  text: string;
  artifact?: string;
}

const MAX_READ_LINES = 2000;
const MAX_READ_BYTES = 8 * 1024 * 1024;

// The MCP default, deliberately not the CLI's. `standard` and `thorough` run
// for minutes and an MCP client times out long before they return, losing the
// scan. A caller who wants more can ask — but has to mean it.
const DEFAULT_BUDGET = "quick";

// Which tools need the tree-sitter grammars warmed. Mirrors cli.ts's
// SCANNING_COMMANDS: everything else re-reads an existing run and must never
// trigger a 22 MB download to do it.
const SCANNING_TOOLS = new Set(["ultrasec_scan", "ultrasec_map", "ultrasec_graph", "ultrasec_investigate"]);

const WRITE_TOOL_NAMES = new Set(["ultrasec_scan", "ultrasec_clean"]);

// tool name → CLI command. The MCP surface is deliberately narrower than the
// CLI's twenty commands: `context`, `narrative` and `implement` want a human
// authoring a file, and `run`/`orchestrate` drive a whole agent fleet — neither
// shape survives a single tool call.
const COMMAND_OF: Record<string, string> = {
  ultrasec_map: "map",
  ultrasec_paths: "paths",
  ultrasec_dossier: "dossier",
  ultrasec_graph: "graph",
  ultrasec_triage: "triage",
  ultrasec_guards: "guards",
  ultrasec_verify: "verify",
  ultrasec_investigate: "investigate",
  ultrasec_revalidate: "revalidate",
  ultrasec_check: "check",
  ultrasec_render: "render",
  ultrasec_tools: "tools",
  ultrasec_scan: "scan",
  ultrasec_clean: "clean",
};

// --------------------------------------------------------------------------
// Argument coercion
// --------------------------------------------------------------------------

function str(v: unknown): string | undefined {
  return typeof v === "string" && v.trim() !== "" ? v : undefined;
}

function num(v: unknown): number | undefined {
  const n = typeof v === "number" ? v : typeof v === "string" && v.trim() !== "" ? Number(v) : NaN;
  return Number.isFinite(n) ? n : undefined;
}

function bool(v: unknown): boolean {
  return v === true || v === "true";
}

function strArray(v: unknown): string[] | undefined {
  return Array.isArray(v) && v.every((x) => typeof x === "string") ? (v as string[]) : undefined;
}

function positive(v: unknown, key: string): number | undefined {
  const n = num(v);
  if (n === undefined) return undefined;
  if (n <= 0) throw new ToolError(`\`${key}\` must be greater than 0.`);
  return n;
}

function requiredRepo(args: Record<string, unknown>, defaults: HandlerDefaults): string {
  const repo = str(args.repo) ?? defaults.defaultRun;
  if (!repo) throw new ToolError("`repo` is required: an absolute path to the repository root.");
  const abs = resolve(repo);
  // A path that doesn't exist must NEVER read as a clean audit — the same rule
  // the scan command enforces, applied before any tool runs.
  if (!isScannableDir(abs)) {
    throw new ToolError(`\`repo\` is not a directory: ${abs}. Refusing to continue — an unscannable path must not report a clean audit.`);
  }
  return abs;
}

function resolveRun(args: Record<string, unknown>, repo: string): string {
  const explicit = str(args.run) ?? str(args.out);
  if (explicit) {
    if (!isAbsolute(explicit)) throw new ToolError("`run` must be an absolute path.");
    return resolve(explicit);
  }
  return join(repo, ".ultrasec");
}

function requireRun(run: string): void {
  if (!existsSync(join(run, "dossier.json")) && !existsSync(join(run, "findings.json"))) {
    throw new ToolError(`no audit run at ${run} — scan the repo first with ultrasec_scan (it writes there). If the run lives elsewhere, pass \`run\`.`);
  }
}

// Build the ParsedArgs a command expects. The MCP layer speaks JSON; the
// command layer speaks CLI flags, and this is the one place that translates.
function toArgs(positional: string[], flags: Record<string, unknown>): ParsedArgs {
  const out: Record<string, string | boolean | (string | boolean)[]> = Object.create(null);
  for (const [k, v] of Object.entries(flags)) {
    if (v === undefined || v === null) continue;
    if (Array.isArray(v)) out[k] = v.map(String);
    else if (typeof v === "boolean") {
      if (v) out[k] = true;
    } else out[k] = String(v);
  }
  return { _: positional, flags: out };
}

// --------------------------------------------------------------------------
// Dispatch
// --------------------------------------------------------------------------

export async function callTool(name: string, args: Record<string, unknown>, defaults: HandlerDefaults = {}): Promise<ToolOutcome> {
  if (WRITE_TOOL_NAMES.has(name) && !defaults.allowWrite) {
    throw new ToolError(`${name} writes to your repository and is disabled — start the server with --allow-write to enable it.`);
  }

  // `tools` and `read` need no repo at all beyond containment.
  if (name === "ultrasec_tools") return runCommand(name, [], {});

  const repo = requiredRepo(args, defaults);
  const run = resolveRun(args, repo);

  if (name === "ultrasec_read") return outcome(name, handleRead(args, repo, run));

  // Serialized per run directory: the audit's worklists are read-merge-write,
  // and a long-lived server can have two calls on the same run in flight.
  //
  // The grammar warm-up happens INSIDE the lock. Awaiting it first would let a
  // later, non-scanning call take the lock while a scan is still warming, so a
  // `paths` fired right after a `scan` would answer "no run yet" from ahead of
  // the scan that was about to create it. Acquisition order now matches
  // request order for every tool.
  return await withRunLock(run, async () => {
    if (SCANNING_TOOLS.has(name)) {
      // warmGrammars announces a downgrade rather than failing: offline, the
      // scan falls back to regex extraction, which finds materially fewer
      // candidates. That is information the caller must carry into its
      // confidence.
      await warmGrammars({ label: "ultrasec" });
    }
    return dispatch(name, args, repo, run);
  });
}

async function dispatch(name: string, args: Record<string, unknown>, repo: string, run: string): Promise<ToolOutcome> {
  switch (name) {
    case "ultrasec_scan":
      return runCommand(name, [], {
        repo,
        out: run,
        budget: str(args.budget) ?? DEFAULT_BUDGET,
        scope: strArray(args.scope),
        include: strArray(args.include),
        exclude: strArray(args.exclude),
        "max-files": positive(args.max_files, "max_files"),
        "max-candidates": positive(args.max_candidates, "max_candidates"),
        "max-depth": positive(args.max_depth, "max_depth"),
        offline: bool(args.offline),
        diff: str(args.diff),
        merge: bool(args.merge),
        json: true,
      });

    case "ultrasec_map":
      return runCommand(name, [], {
        repo,
        out: run,
        scope: strArray(args.scope),
        include: strArray(args.include),
        exclude: strArray(args.exclude),
        "max-files": positive(args.max_files, "max_files"),
        json: true,
      });

    case "ultrasec_clean":
      requireRun(run);
      return runCommand(name, [], { repo, run, all: bool(args.all), "keep-output": bool(args.keep_output), json: true });

    case "ultrasec_dossier": {
      requireRun(run);
      const id = str(args.id);
      if (!id) throw new ToolError("`id` is required — the finding id, from ultrasec_paths.");
      return runCommand(name, [id], { repo, run, json: true });
    }

    case "ultrasec_graph": {
      requireRun(run);
      const target = str(args.target);
      if (!target) throw new ToolError("`target` is required — a repo-relative file path or a symbol name.");
      return runCommand(name, [target], { repo, run, depth: positive(args.depth, "depth"), json: true });
    }

    case "ultrasec_paths":
      requireRun(run);
      return runCommand(name, [], { repo, run, kind: str(args.kind), severity: str(args.severity), json: true });

    case "ultrasec_verify": {
      requireRun(run);
      const shards = positive(args.shards, "shards");
      const shard = num(args.shard);
      if (shards !== undefined && shard !== undefined && (shard < 0 || shard >= shards)) {
        throw new ToolError(`\`shard\` must be between 0 and ${shards - 1}.`);
      }
      return runCommand(name, [], { repo, run, shards, shard, json: true });
    }

    case "ultrasec_check":
      requireRun(run);
      return runCommand(name, [], { repo, run, semantic: bool(args.semantic), "min-severity": str(args.min_severity), json: true });

    case "ultrasec_render":
      requireRun(run);
      return runCommand(name, [], { repo, run, narrative: str(args.narrative), json: true });

    default:
      requireRun(run);
      return runCommand(name, [], { repo, run, json: true });
  }
}

// Invoke the CLI command with its output captured, and turn the result into a
// tool result.
async function runCommand(name: string, positional: string[], flags: Record<string, unknown>): Promise<ToolOutcome> {
  const command = COMMAND_OF[name];
  if (!command) throw new ToolError(`unknown tool: ${name}`);
  const handler = COMMAND_HANDLERS[command];
  if (!handler) throw new ToolError(`no handler for ${command}`);

  const { result: code, stdout, stderr } = await captureOutput(() => handler(toArgs(positional, flags)));

  // Exit 2 is "the request was wrong" — a missing run, a bad flag. That is a
  // tool error the caller can fix.
  if (code === 2) throw new ToolError(stderr.trim() || stdout.trim() || `${command} could not run.`);

  // Exit 1 is a real VERDICT: `check` failing on an unresolvable citation,
  // `verify --apply` failing on a refuted claim. It is not a broken tool, and
  // reporting it as one would tell the model the gate is broken instead of that
  // its audit is. It comes back as a normal result carrying ok:false.
  const payload = parseJson(stdout);
  return {
    text:
      JSON.stringify(
        {
          ...(payload !== undefined
            ? typeof payload === "object" && payload !== null && !Array.isArray(payload)
              ? payload
              : { result: payload }
            : { output: stdout }),
          ok: code === 0,
          exit_code: code,
          ...(stderr.trim() ? { notes: stderr.trim().split("\n") } : {}),
        },
        null,
        2,
      ) + "\n",
    artifact: artifactFor(name, flags),
  };
}

function parseJson(text: string): unknown {
  const trimmed = text.trim();
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return undefined;
  try {
    return JSON.parse(trimmed);
  } catch {
    return undefined;
  }
}

function outcome(name: string, result: unknown): ToolOutcome {
  return { text: JSON.stringify(result, null, 2) + "\n" };
}

// Where an oversized result already exists on disk, so an over-cap refusal can
// point at it instead of just saying no.
function artifactFor(name: string, flags: Record<string, unknown>): string | undefined {
  const run = typeof flags.run === "string" ? flags.run : typeof flags.out === "string" ? flags.out : undefined;
  if (!run) return undefined;
  if (name === "ultrasec_map") return join(run, "MAP.md");
  if (name === "ultrasec_scan") return join(run, "findings.json");
  if (name === "ultrasec_triage") return join(run, "TRIAGE.todo.json");
  if (name === "ultrasec_guards") return join(run, "GUARDS.todo.json");
  if (name === "ultrasec_verify") return join(run, "VERIFY.todo.json");
  if (name === "ultrasec_investigate") return join(run, "INVESTIGATE.todo.json");
  return undefined;
}

function handleRead(args: Record<string, unknown>, repo: string, run: string): unknown {
  const raw = str(args.path);
  if (!raw) throw new ToolError("`path` is required — a repo-relative path, or an absolute path inside the repo or its run.");
  const target = isAbsolute(raw) ? raw : join(repo, raw);

  // Containment on the REALPATH: a symlink inside the repo normalises cleanly
  // as a string and only escapes once the filesystem resolves it. This server
  // can be reached over HTTP.
  let real: string;
  try {
    real = realpathSync(target);
  } catch {
    throw new ToolError(`no such file: ${raw}`);
  }
  const allowed = [repo, run].map((d) => {
    try {
      return realpathSync(d);
    } catch {
      return resolve(d);
    }
  });
  if (!allowed.some((root) => real === root || real.startsWith(root + sep))) {
    throw new ToolError(`path is outside the repo and its run: ${raw}. Use your own file tool for anything else.`);
  }

  const st = statSync(real);
  if (!st.isFile()) throw new ToolError(`not a file: ${raw}`);
  if (st.size > MAX_READ_BYTES) throw new ToolError(`file is too large to read (${st.size} bytes): ${raw}`);

  const lines = readFileSync(real, "utf8").split("\n");
  const total = lines.length;
  const start = Math.max(1, Math.floor(num(args.start_line) ?? 1));
  if (start > total) throw new ToolError(`start_line ${start} is past the end of the file (${total} lines).`);
  const requestedEnd = Math.floor(num(args.end_line) ?? total);
  const end = Math.min(total, Math.max(start, requestedEnd), start + MAX_READ_LINES - 1);

  return {
    path: isAbsolute(raw) ? real : raw,
    start_line: start,
    end_line: end,
    total_lines: total,
    truncated: end < Math.min(total, requestedEnd),
    content: lines.slice(start - 1, end).join("\n"),
  };
}
