import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { flagStr, flagBool, listFlag, numFlag, println, eprintln, type ParsedArgs } from "../util.js";
import { CliAgentRunner } from "../powered/agent.js";
import { runPipeline, ALL_STAGES, type StageName, type PipelineOptions } from "../powered/pipeline.js";

// `ultrasec run --repo <dir> [--out <run>] [--powered] [--agent <name|tpl>]
//    [--cross-check <name|tpl>] [--stages a,b,c] [--no-scan]`
//
// Sequences the AI stages (context → triage → investigate → verify → revalidate →
// narrative → implement → check → render). The DEFAULT (no --powered) makes ZERO external
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

  if (flagBool(args, "json")) {
    println(JSON.stringify(res, null, 2));
    return powered && res.errors.length ? 1 : 0;
  }

  if (!powered) {
    println(`ultrasec run → ${run} (no --powered: emitted worklists, ZERO external calls)`);
    println(`  stages: ${stages.join(" → ")}`);
    println(`  agent TODO — fill each worklist, then apply (or re-run with --powered --agent <cli>):`);
    for (const e of res.emitted) {
      const noApply = e.outName === "CONTEXT.md" || e.outName === "NARRATIVE.json" || e.outName === "REMEDIATION_PRD.md";
      const apply = noApply ? "" : ` → \`ultrasec ${e.stage} --apply ${e.outName} --run ${run}\``;
      println(`    - ${e.stage}: read ${e.worklist}, write ${join(run, e.outName)}${apply}`);
    }
    println(`  then: ultrasec render${stages.includes("narrative") ? " --narrative NARRATIVE.json" : ""} --run ${run}`);
    return 0;
  }

  println(`ultrasec run --powered → ${run} (agent: ${agent}${crossCheck ? `, cross-check: ${crossCheck}` : ""})`);
  println(`  stages: ${stages.join(" → ")}  ·  external agent calls: ${res.externalCalls}`);
  if (res.escalated.length) println(`  ⚠️  cross-check escalated ${res.escalated.length} finding(s) to needs-human: ${res.escalated.join(", ")}`);
  for (const err of res.errors) println(`  ✗ ${err}`);
  println(`  report: ${join(run, "REPORT.md")} · ${join(run, "index.html")}`);
  return res.errors.length ? 1 : 0;
}
