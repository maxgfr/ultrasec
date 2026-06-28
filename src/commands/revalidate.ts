import { resolve } from "node:path";
import { flagStr, flagBool, println, eprintln, type ParsedArgs } from "../util.js";
import { loadDossier } from "../store.js";
import { emitWorklist, readApply, persistFindings, stageFiles } from "../stage.js";
import { loadContextDoc } from "../context.js";
import { buildRevalidateWorklist, renderRevalidateMd, applyRevalidations, parseRevalidations, revalFactsFromWorklist } from "../revalidate.js";

// `ultrasec revalidate --run <dir> [--repo <dir>]`              → emit git-fact worklist
// `ultrasec revalidate --apply <file|dir|a,b,c> --run <dir>`    → fold verdicts back in
// Scope: findings the pipeline already promoted (confirmed / needs-human). The
// git-history false-positive cut — deepsec's "revalidate" pass, ultrasec-style.
export function runRevalidate(args: ParsedArgs): number {
  const run = resolve(flagStr(args, "run") ?? ".ultrasec");
  let dossier: ReturnType<typeof loadDossier>;
  try {
    dossier = loadDossier(run);
  } catch (e) {
    eprintln(`ultrasec revalidate: ${(e as Error).message}`);
    return 2;
  }
  const repo = resolve(flagStr(args, "repo") ?? dossier.manifest.repo);

  const applyPath = flagStr(args, "apply");
  if (applyPath) {
    let inputs: ReturnType<typeof parseRevalidations>;
    try {
      inputs = readApply(applyPath, /revalidat.*\.json$/i, parseRevalidations);
    } catch (e) {
      eprintln(`ultrasec revalidate: cannot read revalidations at ${(e as Error).message}`);
      return 2;
    }
    // Recompute git facts from CURRENT repo state so the drift guard + inferred
    // fixing commits reflect HEAD, not whatever was emitted earlier.
    const facts = revalFactsFromWorklist(buildRevalidateWorklist(dossier, repo));
    const res = applyRevalidations(dossier, inputs, facts);
    persistFindings(run, dossier, res.findings);

    if (flagBool(args, "json")) {
      println(
        JSON.stringify(
          { applied: res.applied, stillValid: res.stillValid, fixed: res.fixed, dismissed: res.dismissed, needsHuman: res.needsHuman, flagged: res.flagged },
          null,
          2,
        ),
      );
      return 0;
    }
    println(`ultrasec revalidate --apply → updated ${run}/findings.json`);
    println(
      `  applied ${res.applied} verdict(s): ${res.stillValid} still-valid · ${res.fixed} fixed · ${res.dismissed} dismissed · ${res.needsHuman} needs-human`,
    );
    for (const fl of res.flagged) println(`  ⚠️  ${fl.id}: ${fl.reason}`);
    return 0;
  }

  // Emit mode
  const items = buildRevalidateWorklist(dossier, repo);
  const todoPath = emitWorklist(run, stageFiles("REVALIDATE"), items, renderRevalidateMd(items, loadContextDoc(run)));

  if (flagBool(args, "json")) {
    println(JSON.stringify(items, null, 2));
    return 0;
  }
  println(`ultrasec revalidate → ${todoPath} (${items.length} item${items.length === 1 ? "" : "s"})`);
  if (!items.length) {
    println(`  no confirmed/needs-human findings to revalidate — run \`verify --apply\` first.`);
  } else {
    println(`  decide still-valid/fixed/false-positive/uncertain per finding, save REVALIDATE.json, then:`);
    println(`  ultrasec revalidate --apply REVALIDATE.json --run ${run}`);
  }
  return 0;
}
