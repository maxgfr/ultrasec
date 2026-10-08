import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { flagBool, flagStr, isScannableDir, listFlag, println, eprintln, quietStdout, type ParsedArgs, type FlagValue } from "../util.js";
import { runScan } from "./scan.js";
import { runCouncil } from "./council.js";
import { cleanRunDir } from "./clean.js";
import { CliAgentRunner } from "../powered/agent.js";
import { runPipeline, ALL_STAGES, type PipelineOptions, type StageName } from "../powered/pipeline.js";
import { loadDossier } from "../store.js";
import { statusLine } from "../render/audit-report.js";
import { wantsMdTwin } from "../stage.js";

// `ultrasec audit --repo <dir> [--out <run>] [--html] [--md] [--full] [--keep-work]
//    [--powered <cli> [--cross-check <cli>]] [--council "<reviewer:model,…>"] [scan flags…]`
//
// ONE command, ONE report. It runs what `run` runs — the scan, the stage
// pipeline, the grounding check, the report — through the same functions
// (`runScan`, `runPipeline`, `deliverReport`), then removes everything but the
// deliverables, and prints the report path and a one-line status.
//
// ── Why it exists ──────────────────────────────────────────────────────────
//
// Getting a report used to take ten commands and left thirty-odd artifacts in
// the run directory — on a 1,245-candidate monorepo, 2.7 MB of graph, 2 MB of
// findings, a 1.2 MB dossier, a 746 KB report and every worklist twice. The
// person who asked for "a report" wanted one file; the agent driving the audit
// burned tokens opening the rest. So: one command, one file, and the
// intermediates only when asked for (`--keep-work`, which an agent adjudicating
// the worklists needs).
//
// ── What it never does ─────────────────────────────────────────────────────
//
// No agent or model is called unless `--powered` / `--council` says so — the
// keyless default is the deterministic engine plus whatever scanners are
// installed (`--offline` removes their network use, as on `scan`). And it never
// presents an undecided run as a clean one: with code candidates nobody read,
// the report opens with a DRAFT banner and the status line says why.
//
// A second `audit` on the same `--out` merges into the existing dossier
// (`scan --merge`), so verdicts already applied there survive the re-scan and
// the new report reflects them. `--fresh` starts over.

/** Flags `audit` consumes itself; everything else is passed to `scan`. */
const AUDIT_ONLY = new Set([
  "html",
  "md",
  "full",
  "keep-work",
  "powered",
  "agent",
  "cross-check",
  "council",
  "stages",
  "fresh",
  "strict",
  "json",
  "out",
  "run",
  "no-journal",
  "report",
]);

/** The agent CLI `--powered` names: `--powered <cli>`, `--powered=<cli>`, or `--powered --agent <cli>`. */
function poweredAgent(args: ParsedArgs): { powered: boolean; agent?: string } {
  const v = args.flags.powered;
  if (v === undefined) return { powered: false };
  const values = (Array.isArray(v) ? v : [v]).filter((x): x is string => typeof x === "string" && x !== "true");
  // `powered` is a boolean flag in the parser, so `--powered <cli>` leaves the
  // CLI as the first positional after the command.
  const agent = values[0] ?? flagStr(args, "agent") ?? args._[1];
  return { powered: true, agent };
}

export async function runAudit(args: ParsedArgs): Promise<number> {
  const repo = resolve(flagStr(args, "repo") ?? ".");
  const run = resolve(flagStr(args, "out") ?? flagStr(args, "run") ?? ".ultrasec");
  const json = flagBool(args, "json");
  const keepWork = flagBool(args, "keep-work");
  const fail = (msg: string, code = 2): number => {
    eprintln(`ultrasec audit: ${msg}`);
    return code;
  };

  if (!isScannableDir(repo)) return fail(`--repo '${repo}' is not a directory. Aborting — an unscannable path must not report a clean audit.`);
  const { powered, agent } = poweredAgent(args);
  if (powered && !agent) return fail(`--powered needs the agent CLI to drive: \`--powered <cli>\` (its keys live in that CLI, never in ultrasec).`);
  const requested = listFlag(args, "stages");
  const unknown = (requested ?? []).filter((s) => !(ALL_STAGES as readonly string[]).includes(s));
  if (unknown.length) return fail(`unknown stage(s): ${unknown.join(", ")} (known: ${ALL_STAGES.join(", ")}).`);

  // 1. Scan — the real `scan`, every passthrough flag honoured, merging into an
  //    existing run so its adjudications survive.
  const scanFlags: Record<string, FlagValue> = Object.create(null);
  for (const [k, v] of Object.entries(args.flags)) if (!AUDIT_ONLY.has(k)) scanFlags[k] = v;
  scanFlags.repo = repo;
  scanFlags.out = run;
  if (!flagBool(args, "fresh") && existsSync(join(run, "findings.json"))) scanFlags.merge = true;
  const scanned = await quietStdout(() => runScan({ _: ["scan"], flags: scanFlags }));
  if (scanned.result === 2) {
    if (scanned.stdout) eprintln(scanned.stdout);
    return fail(`scan failed — nothing was reported.`);
  }

  // 2. Council (opt-in) — other model families review a snapshot; their
  //    candidates stay a worklist for a human/agent to decide, and their usage
  //    lands in the report's engines annex.
  const council = flagStr(args, "council");
  const notes: string[] = [];
  if (council) {
    const c = await quietStdout(() => runCouncil({ _: ["council"], flags: { run, repo, models: council } }));
    if (c.result !== 0) notes.push(`council exited ${c.result} — see ${join(run, "council")} (kept with --keep-work)`);
  }

  // 3. The stage pipeline + grounding check + THE report — `run`'s own code.
  //    Keyless and not keeping the work, the worklists would be deleted a
  //    moment after being written, so none are emitted.
  const stages = (powered || keepWork ? ALL_STAGES.filter((s) => !requested || requested.includes(s)) : []) as StageName[];
  const opts: PipelineOptions = {
    repo,
    run,
    powered,
    stages,
    scan: false,
    md: wantsMdTwin(args),
    report: { html: flagBool(args, "html"), md: flagBool(args, "md"), full: flagBool(args, "full") },
  };
  if (powered && agent) {
    opts.runner = new CliAgentRunner(agent);
    const cross = flagStr(args, "cross-check");
    if (cross) opts.crossRunner = new CliAgentRunner(cross);
  }
  let res: ReturnType<typeof runPipeline>;
  try {
    res = (await quietStdout(() => runPipeline(opts))).result;
  } catch (e) {
    return fail((e as Error).message);
  }
  const dossier = loadDossier(run);
  const status = statusLine(dossier, res.report.status);

  // 4. One report, nothing else — unless the work is wanted.
  const removed = keepWork ? [] : cleanRunDir(run).removed;

  for (const n of res.notices) eprintln(`ultrasec audit: ⚠️  ${n}`);
  for (const e of res.errors) eprintln(`ultrasec audit: ✗ ${e}`);
  for (const n of notes) eprintln(`ultrasec audit: ⚠️  ${n}`);
  const code = !res.grounded || (powered && res.errors.length) || (flagBool(args, "strict") && res.report.status.draft) ? 1 : 0;

  if (json) {
    println(
      JSON.stringify(
        {
          report: res.report.written,
          draft: res.report.status.draft,
          reasons: res.report.status.reasons,
          status,
          grounded: res.grounded,
          externalCalls: res.externalCalls,
          worklists: keepWork ? res.emitted.map((e) => e.worklist) : [],
          removed: removed.length,
        },
        null,
        2,
      ),
    );
    return code;
  }
  println(res.report.written.join(" · "));
  println(`  ${status}`);
  if (keepWork && res.emitted.length)
    println(`  worklists kept: fill the *.todo.json in ${run}, \`--apply\` each, then \`ultrasec render --run ${run}\` and \`ultrasec clean --run ${run}\``);
  return code;
}
