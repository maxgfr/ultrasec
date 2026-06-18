import { resolve } from "node:path";
import { flagStr, flagBool, println, eprintln, type ParsedArgs } from "../util.js";
import { loadDossier } from "../store.js";
import { emitWorklist, stageFiles } from "../stage.js";
import { loadContextDoc } from "../context.js";
import { buildImplementWorklist, loadNarrative, renderImplementMd } from "../implement.js";

// `ultrasec implement --run <dir> [--narrative <file>] [--json]`
// Emit-only (mirrors `narrative`): a remediation-PRD DRAFT (IMPLEMENT.md) + a structured
// worklist (IMPLEMENT.todo.json) built from confirmed (→ fix) / needs-human (→ investigate)
// findings, folding the grounded NARRATIVE.json (fixes, patches, root causes) when present.
// There is NO `--apply`: it persists nothing and NEVER changes a finding's status/severity/set.
// Feed IMPLEMENT.md to the local `to-prd` skill to author the PRD, or to an implementer/AI.
export function runImplement(args: ParsedArgs): number {
  const run = resolve(flagStr(args, "run") ?? ".ultrasec");
  let dossier;
  try {
    dossier = loadDossier(run);
  } catch (e) {
    eprintln(`ultrasec implement: ${(e as Error).message}`);
    return 2;
  }

  const narrFile = flagStr(args, "narrative");
  const narrative = loadNarrative(run, dossier, narrFile ? resolve(narrFile) : undefined);
  const wl = buildImplementWorklist(dossier, narrative);
  const todoPath = emitWorklist(run, stageFiles("IMPLEMENT"), wl, renderImplementMd(wl, loadContextDoc(run)));

  if (flagBool(args, "json")) {
    println(JSON.stringify(wl, null, 2));
    return 0;
  }
  println(`ultrasec implement → ${todoPath} (${wl.fixes.length} fix · ${wl.investigations.length} investigate · ${wl.rootCauses.length} root cause${wl.rootCauses.length === 1 ? "" : "s"})`);
  if (!wl.fixes.length && !wl.investigations.length) {
    println(`  nothing confirmed/needs-human yet — run \`verify --apply\` first.`);
  } else {
    println(`  next: feed ${run}/IMPLEMENT.md to the \`to-prd\` skill to author the remediation PRD, or hand it to an implementer.`);
  }
  return 0;
}
