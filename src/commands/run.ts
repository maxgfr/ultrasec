import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { flagStr, flagBool, listFlag, numFlag, println, eprintln, type ParsedArgs, listCapped } from "../util.js";
import { wantsMdTwin } from "../stage.js";
import { CliAgentRunner } from "../powered/agent.js";
import { runPipeline, ALL_STAGES, type StageName, type PipelineOptions } from "../powered/pipeline.js";

// `ultrasec run --repo <dir> [--out <run>] [--powered] [--agent <name|tpl>]
//    [--cross-check <name|tpl>] [--stages a,b,c] [--no-scan]`
//
// Sequences the AI stages (context → assumptions → triage → investigate → verify →
// revalidate → variants → narrative → implement → check → render). The DEFAULT (no --powered) makes ZERO external
// calls: it only scans + emits the worklists and prints the agent TODO list. With
// --powered it drives the configured agent CLI per worklist (the keys live in that
// CLI, not in ultrasec); --cross-check adds a second agent whose high/critical
// disagreement on verify/revalidate escalates a finding to needs-human.
export function runRun(args: ParsedArgs): number {
  const repo = resolve(flagStr(args, "repo") ?? ".");
  const run = resolve(flagStr(args, "out") ?? ".ultrasec");
  const powered = flagBool(args, "powered");
  const noScan = flagBool(args, "no-scan");

  // Stage selection: keep ALL_STAGES' canonical order, filtered to --stages if given.
  const requested = listFlag(args, "stages");
  if (requested) {
    const unknown = requested.filter((s) => !(ALL_STAGES as readonly string[]).includes(s));
    if (unknown.length) {
      eprintln(`ultrasec run: unknown stage(s): ${unknown.join(", ")} (known: ${ALL_STAGES.join(", ")}).`);
      return 2;
    }
  }
  const stages = ALL_STAGES.filter((s) => !requested || requested.includes(s)) as StageName[];

  if (noScan && !existsSync(join(run, "findings.json"))) {
    eprintln(`ultrasec run: --no-scan but no dossier at ${run} — run \`scan\` first or drop --no-scan.`);
    return 2;
  }

  const agent = flagStr(args, "agent") ?? "claude";
  const crossCheck = flagStr(args, "cross-check");

  const opts: PipelineOptions = {
    repo,
    run,
    powered,
    stages,
    scan: !noScan,
    scanOpts: {
      scope: listFlag(args, "scope"),
      include: listFlag(args, "include"),
      exclude: listFlag(args, "exclude"),
      maxFiles: numFlag(args, "max-files"),
      gitignore: flagBool(args, "gitignore"),
    },
    md: wantsMdTwin(args),
    report: { html: flagBool(args, "html"), md: flagBool(args, "md"), full: flagBool(args, "full") },
  };
  if (powered) {
    opts.runner = new CliAgentRunner(agent);
    if (crossCheck) opts.crossRunner = new CliAgentRunner(crossCheck);
  }

  let res: ReturnType<typeof runPipeline>;
  try {
    res = runPipeline(opts);
  } catch (e) {
    eprintln(`ultrasec run: ${(e as Error).message}`);
    return 2;
  }

  // The summary, not the transcript: the worklists are on disk, and `actions`
  // repeated every one of them by name.
  if (flagBool(args, "json")) {
    println(
      JSON.stringify({
        powered,
        stages,
        externalCalls: res.externalCalls,
        emitted: res.emitted.map((e) => ({ stage: e.stage, worklist: e.worklist })),
        escalated: res.escalated.length,
        errors: res.errors,
        notices: res.notices,
        report: res.report,
        grounded: res.grounded,
      }),
    );
    return powered && res.errors.length ? 1 : 0;
  }

  // Notices belong to both branches: a negation in CONTEXT.md the code
  // contradicts is exactly what a non-powered run — where a human is about to
  // fill the worklists from that document — needs told before it starts.
  const printNotices = (): void => {
    for (const n of res.notices) println(`  ⚠️  ${n}`);
  };

  if (!powered) {
    println(`ultrasec run → ${run} (no --powered: emitted worklists, ZERO external calls)`);
    println(`  stages: ${stages.join(" → ")}`);
    printNotices();
    println(`  agent TODO — fill each worklist, then apply (or re-run with --powered --agent <cli>):`);
    for (const e of res.emitted) {
      const noApply = e.outName === "CONTEXT.md" || e.outName === "NARRATIVE.json" || e.outName === "REMEDIATION_PRD.md";
      const apply = noApply ? "" : ` → \`ultrasec ${e.stage} --apply ${e.outName} --run ${run}\``;
      println(`    - ${e.stage}: read ${e.worklist}, write ${join(run, e.outName)}${apply}`);
    }
    println(`  report (draft until the worklists are applied): ${res.report.written.join(" · ")}`);
    println(`  then: ultrasec render --run ${run}`);
    return 0;
  }

  println(`ultrasec run --powered → ${run} (agent: ${agent}${crossCheck ? `, cross-check: ${crossCheck}` : ""})`);
  println(`  stages: ${stages.join(" → ")}  ·  external agent calls: ${res.externalCalls}`);
  if (res.escalated.length) println(`  ⚠️  ${listCapped(`cross-check escalated ${res.escalated.length} finding(s) to needs-human`, res.escalated)}`);
  printNotices();
  for (const err of res.errors) println(`  ✗ ${err}`);
  println(`  report: ${res.report.written.join(" · ")}`);
  return res.errors.length ? 1 : 0;
}
