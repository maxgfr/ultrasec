import { resolve } from "node:path";
import { flagStr, flagBool, println, eprintln, type ParsedArgs } from "../util.js";
import { loadDossier } from "../store.js";
import { emitWorklist, readApply, persistFindings, stageFiles } from "../stage.js";
import { loadContextDoc } from "../context.js";
import { buildTriageWorklist, renderTriageMd, applyTriage, parseTriage } from "../triage.js";

// `ultrasec triage --run <dir>`                           → emit the open-candidate worklist
// `ultrasec triage --apply <file|dir|a,b,c> --run <dir>`  → fold noise/keep back in
// The cheap first pass: clear obvious noise on low/med/info before the expensive
// per-finding verify. A `noise` verdict on high/critical is ignored (kept open).
export function runTriage(args: ParsedArgs): number {
  const run = resolve(flagStr(args, "run") ?? ".ultrasec");
  let dossier;
  try {
    dossier = loadDossier(run);
  } catch (e) {
    eprintln(`ultrasec triage: ${(e as Error).message}`);
    return 2;
  }

  const applyPath = flagStr(args, "apply");
  if (applyPath) {
    let inputs;
    try {
      inputs = readApply(applyPath, /triage.*\.json$/i, parseTriage);
    } catch (e) {
      eprintln(`ultrasec triage: cannot read triage verdicts at ${(e as Error).message}`);
      return 2;
    }
    const res = applyTriage(dossier, inputs);
    persistFindings(run, dossier, res.findings);

    if (flagBool(args, "json")) {
      println(JSON.stringify({ applied: res.applied, dismissed: res.dismissed, kept: res.kept }, null, 2));
      return 0;
    }
    println(`ultrasec triage --apply → updated ${run}/findings.json`);
    println(`  applied ${res.applied} verdict(s): ${res.dismissed} dismissed as noise`);
    if (res.kept.length) {
      println(`  kept open (high/critical 'noise' ignored — must go through verify):`);
      for (const k of res.kept) println(`    - ${k.id} [${k.severity}]`);
    }
    return 0;
  }

  // Emit mode
  const items = buildTriageWorklist(dossier);
  const todoPath = emitWorklist(run, stageFiles("TRIAGE"), items, renderTriageMd(items, loadContextDoc(run)));

  if (flagBool(args, "json")) {
    println(JSON.stringify(items, null, 2));
    return 0;
  }
  println(`ultrasec triage → ${todoPath} (${items.length} open candidate${items.length === 1 ? "" : "s"})`);
  if (!items.length) {
    println(`  no open candidates to triage.`);
  } else {
    println(`  mark each noise/keep, save TRIAGE.json, then:`);
    println(`  ultrasec triage --apply TRIAGE.json --run ${run}`);
  }
  return 0;
}
