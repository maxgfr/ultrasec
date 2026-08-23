import { resolve } from "node:path";
import { flagStr, flagBool, println, eprintln, type ParsedArgs } from "../util.js";
import { loadDossier } from "../store.js";
import { emitWorklist, readApply, persistFindings, stageFiles } from "../stage.js";
import { surfaceDropped } from "../apply-parse.js";
import { loadContextDoc } from "../context.js";
import { buildTriageWorklist, renderTriageMd, applyTriage, parseTriage } from "../triage.js";
import { SURFACE_FILTERS, type SurfaceFilter } from "../orchestrate.js";
import { surfaceOf } from "../surface.js";

// `ultrasec triage --run <dir> [--surface code]`          → emit the open-candidate worklist
// `ultrasec triage --apply <file|dir|a,b,c> --run <dir>`  → fold noise/keep back in
// The cheap first pass: clear obvious noise on low/med/info before the expensive
// per-finding verify. A `noise` verdict on high/critical is ignored (kept open).
export function runTriage(args: ParsedArgs): number {
  const run = resolve(flagStr(args, "run") ?? ".ultrasec");
  let dossier: ReturnType<typeof loadDossier>;
  try {
    dossier = loadDossier(run);
  } catch (e) {
    eprintln(`ultrasec triage: ${(e as Error).message}`);
    return 2;
  }

  const applyPath = flagStr(args, "apply");
  if (applyPath) {
    let parsed: ReturnType<typeof parseTriage>;
    try {
      parsed = readApply(applyPath, /triage.*\.json$/i, parseTriage);
    } catch (e) {
      eprintln(`ultrasec triage: cannot read triage verdicts at ${(e as Error).message}`);
      return 2;
    }
    const strict = flagBool(args, "strict");
    const res = applyTriage(dossier, parsed.rows);
    persistFindings(run, dossier, res.findings);

    if (flagBool(args, "json")) {
      println(JSON.stringify({ applied: res.applied, dismissed: res.dismissed, kept: res.kept, dropped: parsed.dropped }, null, 2));
      return strict && parsed.dropped.length > 0 ? 1 : 0;
    }
    println(`ultrasec triage --apply → updated ${run}/findings.json`);
    println(`  applied ${res.applied} verdict(s): ${res.dismissed} dismissed as noise`);
    if (res.kept.length) {
      println(`  kept open (high/critical 'noise' ignored — must go through verify):`);
      for (const k of res.kept) println(`    - ${k.id} [${k.severity}]`);
    }
    return surfaceDropped(parsed.dropped, strict, println);
  }

  // Emit mode
  const surfaceFlag = flagStr(args, "surface");
  if (surfaceFlag !== undefined && !(SURFACE_FILTERS as readonly string[]).includes(surfaceFlag)) {
    eprintln(`ultrasec triage: unknown --surface "${surfaceFlag}" — expected one of: ${SURFACE_FILTERS.join(", ")}.`);
    return 2;
  }
  const surface = (surfaceFlag ?? "all") as SurfaceFilter;
  // Narrowing the WORKLIST is safe; narrowing the fold is not, so `--apply`
  // takes no surface. A verdict file names its ids and folds exactly those.
  const scoped = surface === "all" ? dossier : { ...dossier, findings: dossier.findings.filter((f) => surfaceOf(f) === surface) };
  const items = buildTriageWorklist(scoped);
  const todoPath = emitWorklist(run, stageFiles("TRIAGE"), items, renderTriageMd(items, loadContextDoc(run)));

  if (flagBool(args, "json")) {
    println(JSON.stringify(items, null, 2));
    return 0;
  }
  println(`ultrasec triage → ${todoPath} (${items.length} open candidate${items.length === 1 ? "" : "s"}${surface === "all" ? "" : `, surface ${surface}`})`);
  if (!items.length) {
    println(`  no open candidates to triage.`);
  } else {
    println(`  mark each noise/keep, save TRIAGE.json, then:`);
    println(`  ultrasec triage --apply TRIAGE.json --run ${run}`);
  }
  return 0;
}
