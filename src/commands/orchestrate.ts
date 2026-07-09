import { existsSync, realpathSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { listPhases, orchestrateRun, PHASES } from "../orchestrate.js";
import { eprintln, flagBool, flagStr, println, type ParsedArgs } from "../util.js";

// `ultrasec orchestrate --run <dir> [--phase <name>] [--eco] [--list]`
// Emit the run's multi-agent orchestration from its CURRENT worklists: one
// <phase>.workflow.mjs per ready phase (real ids batched in), the dispatch
// contracts (agents/<role>.md) and a sequential RUNBOOK.md, all under
// <run>/orchestration/. Subagents RETURN fragments; every `--apply` fold stays
// with the orchestrator (one writer).
export function runOrchestrate(args: ParsedArgs): number {
  const runFlag = flagStr(args, "run");
  if (!runFlag) {
    eprintln("ultrasec orchestrate: --run <dir> is required (the run dir holding the audit dossier + worklists).");
    return 2;
  }
  // The engine's own absolute path — baked into the emitted workflows/contracts
  // so subagents (which share no cwd) can invoke it. realpathSync resolves the
  // `.bin` symlink npm/npx creates, same as the entrypoint guard in cli.ts.
  const engineAbs = realpathSync(fileURLToPath(import.meta.url));

  if (flagBool(args, "list")) {
    if (!existsSync(runFlag)) {
      eprintln(`ultrasec orchestrate: run dir not found: ${runFlag}.`);
      return 2;
    }
    println(JSON.stringify({ phases: listPhases(runFlag, engineAbs) }, null, 2));
    return 0;
  }

  const res = orchestrateRun(runFlag, engineAbs, {
    phase: flagStr(args, "phase"),
    eco: flagBool(args, "eco"),
  });
  if (res.exitCode !== 0) {
    for (const e of res.errors) eprintln(`ultrasec orchestrate: ${e}`);
    return res.exitCode;
  }
  println("ultrasec orchestrate: generated");
  for (const w of res.written) println(`  ${w}`);
  for (const n of res.notices) eprintln(`ultrasec orchestrate: note — ${n}`);
  const workflows = res.written.filter((w) => w.endsWith(".workflow.mjs"));
  if (workflows.length) {
    println("");
    for (const w of workflows) println(`Launch: Workflow({ scriptPath: ${JSON.stringify(w)} })`);
    println("Then merge the returned fragments into one apply file and run the `--apply` fold shown at the end of each workflow (you stay the sole writer).");
  } else {
    println(`Follow ${join(runFlag, "orchestration", "RUNBOOK.md")} sequentially (the eco path).`);
  }
  // Surface the valid phase names once, so a scripted caller can discover them without --help.
  if (flagStr(args, "phase") === undefined && workflows.length === 0 && !flagBool(args, "eco")) {
    eprintln(`ultrasec orchestrate: no ready phase — phases are ${PHASES.join(", ")} (see --list).`);
  }
  return 0;
}
