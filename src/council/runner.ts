import { spawn } from "node:child_process";
import { appendFileSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";
import { ADAPTERS, onPath, type CouncilCli, type ModelSpec, type Reviewer } from "./adapters.js";
import { argvMessage, finalizeMessage, type Lang, type Phase } from "./brief.js";
import { addUsage, digest, emptyUsage, isContractShaped, watchLine, type Digest, type Failure } from "./events.js";
import { reviewerDir, type Attempt, type ReviewerRecord, type ReviewerStatus } from "./ledger.js";
import { redactJsonLine, redactReviewerText } from "./redact.js";
import { councilEnv } from "./snapshot.js";

// Running the reviewers: in parallel, each on the snapshot, each with an
// emptied environment, each with its own timeout — and each given a second
// chance that costs one turn instead of a whole run.

export interface SpawnRequest {
  argv: string[];
  cwd: string;
  env: Record<string, string>;
  timeoutMs: number;
  /** Called per output line as it arrives; returning a reason stops the process. */
  onLine?: (stream: "stdout" | "stderr", line: string) => "budget" | "failure" | undefined;
}

export interface SpawnResult {
  code: number | null;
  stdout: string;
  stderr: string;
  /** Why WE stopped it, when we did. */
  killed?: "timeout" | "budget" | "failure";
  durationMs: number;
}

export type CouncilSpawner = (req: SpawnRequest) => Promise<SpawnResult>;

/** Async spawn, argv only, line-watched, killed on timeout or on the watcher's word. */
export const defaultSpawner: CouncilSpawner = (req) =>
  new Promise((resolve) => {
    const started = Date.now();
    const [cmd, ...args] = req.argv;
    let killed: SpawnResult["killed"];
    const chunks = { stdout: [] as string[], stderr: [] as string[] };
    const partial = { stdout: "", stderr: "" };
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(cmd!, args, { cwd: req.cwd, env: req.env, stdio: ["ignore", "pipe", "pipe"] });
    } catch (e) {
      resolve({ code: null, stdout: "", stderr: (e as Error).message, durationMs: 0 });
      return;
    }
    const stop = (why: NonNullable<SpawnResult["killed"]>): void => {
      if (killed) return;
      killed = why;
      child.kill("SIGTERM");
      setTimeout(() => child.kill("SIGKILL"), 5000).unref();
    };
    const timer = setTimeout(() => stop("timeout"), req.timeoutMs);
    for (const stream of ["stdout", "stderr"] as const) {
      child[stream]!.setEncoding("utf8");
      child[stream]!.on("data", (d: string) => {
        chunks[stream].push(d);
        if (!req.onLine) return;
        const lines = (partial[stream] + d).split("\n");
        partial[stream] = lines.pop() ?? "";
        for (const line of lines) {
          const verdict = req.onLine(stream, line);
          if (verdict) stop(verdict);
        }
      });
    }
    let spawnError = "";
    child.on("error", (e) => {
      spawnError = e.message;
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({
        code: typeof code === "number" ? code : null,
        stdout: chunks.stdout.join(""),
        stderr: chunks.stderr.join("") + (spawnError ? `\n${spawnError}` : ""),
        ...(killed ? { killed } : {}),
        durationMs: Date.now() - started,
      });
    });
  });

export interface RunnerContext {
  run: string;
  snapshot: string;
  phase: Phase;
  lang: Lang;
  timeoutMs: number;
  /** Stop a reviewer once its reported cost passes this (USD). */
  maxCost?: number;
  maxTurns: number;
  fallbacks: ModelSpec[];
  spawner: CouncilSpawner;
  /** Test seam: replace a CLI's binary with an argv prefix (a fake CLI). */
  commands?: Partial<Record<CouncilCli, string[]>>;
  /** Base environment the emptied one is derived from (HOME, PATH). */
  baseEnv?: NodeJS.ProcessEnv;
}

/** The closing turn is short by construction; it never needs the full budget. */
const FINALIZE_TIMEOUT_MS = 15 * 60 * 1000;

interface AttemptOutcome {
  attempt: Attempt;
  digest: Digest;
}

function statusOf(d: Digest, res: SpawnResult): ReviewerStatus {
  if (res.killed === "budget") return "budget";
  if (res.killed === "timeout") return "timeout";
  if (isContractShaped(d.text)) return "ok";
  if (d.failure) return d.failure.kind === "error" ? "failed" : d.failure.kind;
  return res.code === 0 ? "no-report" : "failed";
}

/** One invocation of one CLI: fresh, or resuming `session` for one closing turn. */
async function attempt(ctx: RunnerContext, reviewer: Reviewer, spec: ModelSpec, session: string | undefined): Promise<AttemptOutcome> {
  const adapter = ADAPTERS[spec.cli];
  const resume = session !== undefined;
  const dir = reviewerDir(ctx.run, ctx.phase, reviewer.name);
  const input = {
    model: spec.model,
    dir: ctx.snapshot,
    message: resume ? finalizeMessage(ctx.lang, ctx.phase, reviewer.name) : argvMessage(ctx.lang, ctx.phase, reviewer.name),
    title: `ultrasec council ${ctx.phase} ${reviewer.name}`,
    maxTurns: ctx.maxTurns,
    ...(session ? { session } : {}),
  };
  const args = resume ? adapter.resume(input) : adapter.start(input);
  const base = { cli: spec.cli, model: spec.model, resume, exit: null, durationMs: 0, usage: emptyUsage(adapter.usageExposed) };
  if (!args) {
    const failure: Failure = { kind: "error", message: `${spec.cli} cannot resume a session it did not name` };
    return { attempt: { ...base, status: "failed", failure }, digest: { usage: base.usage, text: "", failure, toolCalls: 0 } };
  }
  const env = councilEnv(adapter.env?.(spec.model) ?? {}, ctx.baseEnv);
  const prefix = ctx.commands?.[spec.cli];
  if (!prefix && !onPath(adapter.bin, env.PATH)) {
    const failure: Failure = { kind: "error", message: `${adapter.bin} is not on PATH` };
    return { attempt: { ...base, status: "not-installed", failure }, digest: { usage: base.usage, text: "", failure, toolCalls: 0 } };
  }

  let cost = 0;
  let watched: Failure | undefined;
  const res = await ctx.spawner({
    argv: [...(prefix ?? [adapter.bin]), ...args],
    cwd: ctx.snapshot,
    env,
    timeoutMs: resume ? Math.min(ctx.timeoutMs, FINALIZE_TIMEOUT_MS) : ctx.timeoutMs,
    onLine: (stream, line) => {
      const w = watchLine(adapter.format, stream, line);
      if (w.cost) cost += w.cost;
      if (ctx.maxCost !== undefined && cost > ctx.maxCost) return "budget";
      // A provider stop does not recover by waiting: stop paying for the wait.
      if (w.failure && w.failure.kind !== "error") {
        watched = w.failure;
        return "failure";
      }
      return undefined;
    },
  });
  const d = digest(adapter.format, res.stdout, res.stderr, res.code);
  if (watched && !d.failure && !isContractShaped(d.text)) d.failure = watched;

  // Logs, redacted on the way in: the event stream carries every file the
  // reviewer read, verbatim.
  mkdirSync(dir, { recursive: true });
  const marker = JSON.stringify({ type: "ultrasec.attempt", cli: spec.cli, model: spec.model, resume, exit: res.code, killed: res.killed ?? null });
  if (adapter.format !== "text") {
    const lines = res.stdout.split("\n").filter((l) => l.trim());
    appendFileSync(join(dir, "events.jsonl"), [marker, ...lines.map(redactJsonLine)].join("\n") + "\n");
  }
  if (res.stderr.trim()) appendFileSync(join(dir, "err.log"), `--- ${spec.cli}:${spec.model}${resume ? " (resume)" : ""}\n${redactReviewerText(res.stderr)}\n`);

  const status = statusOf(d, res);
  return {
    attempt: {
      ...base,
      status,
      exit: res.code,
      durationMs: res.durationMs,
      usage: d.usage,
      ...(d.failure ? { failure: { ...d.failure, message: redactReviewerText(d.failure.message) } } : {}),
    },
    digest: d,
  };
}

/** Statuses a one-turn resume of the SAME model can cure: the context is paid for, the model still answers. */
const CURABLE_IN_PLACE: ReadonlySet<ReviewerStatus> = new Set(["budget", "timeout", "no-report"]);

/**
 * Run one reviewer to a report, or to a recorded reason why there is none.
 *
 * 1. The full review on the reviewer's own model.
 * 2. Cut by OUR budget or timeout, or finished without the report? Resume the
 *    same session, same model, for one turn: "stop exploring, write it now".
 * 3. Still nothing — quota, credit, an upstream 504? Walk `--fallback` (same
 *    CLI only: a session belongs to the CLI that opened it), resuming the
 *    session when there is one, starting fresh when there is not. A 504 from
 *    one free model just hands the turn to the next.
 */
export async function runReviewer(ctx: RunnerContext, reviewer: Reviewer, prior?: ReviewerRecord): Promise<ReviewerRecord> {
  const dir = reviewerDir(ctx.run, ctx.phase, reviewer.name);
  const attempts: Attempt[] = [];
  let session = prior?.session;
  let best: Digest | undefined;
  let resetAt = prior?.resetAt;
  const record = (o: AttemptOutcome): boolean => {
    attempts.push(o.attempt);
    session ??= o.digest.session;
    if (o.digest.failure?.resetAt) resetAt = o.digest.failure.resetAt;
    if (o.attempt.status === "ok" || (!best?.text && o.digest.text)) best = o.digest;
    return o.attempt.status === "ok";
  };

  let done = false;
  if (!prior) {
    // A fresh pass replaces the previous one's logs; a resume appends to them.
    // (`brief.md` is the caller's, written just before, and stays.)
    for (const f of ["events.jsonl", "err.log", "out.md"]) rmSync(join(dir, f), { force: true });
    mkdirSync(dir, { recursive: true });
    done = record(await attempt(ctx, reviewer, reviewer, undefined));
  }
  const last = (): ReviewerStatus | undefined => attempts.at(-1)?.status ?? prior?.status;
  if (!done && session && (prior || CURABLE_IN_PLACE.has(last()!))) {
    done = record(await attempt(ctx, reviewer, reviewer, session));
  }
  if (!done && last() !== "not-installed") {
    for (const fb of ctx.fallbacks.filter((f) => f.cli === reviewer.cli)) {
      done = record(await attempt(ctx, reviewer, fb, session));
      if (done) break;
    }
  }

  const status = done ? "ok" : (last() ?? "failed");
  let report = prior?.report;
  if (best?.text) {
    writeFileSync(join(dir, "out.md"), `${redactReviewerText(best.text)}\n`);
    report = relative(ctx.run, join(dir, "out.md")).split("\\").join("/");
  }
  const allAttempts = [...(prior?.attempts ?? []), ...attempts];
  return {
    name: reviewer.name,
    phase: ctx.phase,
    cli: reviewer.cli,
    model: reviewer.model,
    ...(reviewer.focus ? { focus: reviewer.focus } : {}),
    status,
    ...(session ? { session } : {}),
    ...(resetAt && status !== "ok" ? { resetAt } : {}),
    attempts: allAttempts,
    usage: allAttempts.reduce((acc, a) => addUsage(acc, a.usage), emptyUsage(ADAPTERS[reviewer.cli].usageExposed)),
    ...(report ? { report } : {}),
  };
}
