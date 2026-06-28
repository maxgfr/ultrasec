import { resolve } from "node:path";
import { flagStr, flagBool, println, eprintln, type ParsedArgs } from "../util.js";
import { loadDossier } from "../store.js";
import { emitWorklist, stageFiles } from "../stage.js";
import { loadContextDoc } from "../context.js";
import { buildNarrativeWorklist, renderNarrativeWorklistMd } from "../narrative.js";

// `ultrasec narrative --run <dir> [--json]`
// Emit the report-narrative worklist (reportable findings + a Narrative scaffold).
// The agent authors NARRATIVE.json; `render --narrative NARRATIVE.json` folds it in
// as additive, AI-marked sections. There is no `--apply`: the narrative is layered
// on at render time and NEVER changes a finding's status/severity/set.
export function runNarrative(args: ParsedArgs): number {
  const run = resolve(flagStr(args, "run") ?? ".ultrasec");
  let dossier: ReturnType<typeof loadDossier>;
  try {
    dossier = loadDossier(run);
  } catch (e) {
    eprintln(`ultrasec narrative: ${(e as Error).message}`);
    return 2;
  }

  const wl = buildNarrativeWorklist(dossier);
  const todoPath = emitWorklist(run, stageFiles("NARRATIVE"), wl, renderNarrativeWorklistMd(wl, loadContextDoc(run)));

  if (flagBool(args, "json")) {
    println(JSON.stringify(wl, null, 2));
    return 0;
  }
  println(`ultrasec narrative → ${todoPath} (${wl.findings.length} reportable finding${wl.findings.length === 1 ? "" : "s"})`);
  if (!wl.findings.length) {
    println(`  nothing confirmed/needs-human yet — run \`verify --apply\` first.`);
  } else {
    println(`  author NARRATIVE.json (see NARRATIVE.md), then:`);
    println(`  ultrasec render --narrative NARRATIVE.json --run ${run}`);
  }
  return 0;
}
