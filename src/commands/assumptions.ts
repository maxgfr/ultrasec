import { writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { flagStr, flagBool, listFlag, numFlag, println, eprintln, type ParsedArgs } from "../util.js";
import { loadDossier } from "../store.js";
import { emitWorklist, readApply, stageFiles } from "../stage.js";
import { surfaceDropped } from "../apply-parse.js";
import { loadContextDoc } from "../context.js";
import { scanRepo } from "../scan.js";
import { buildAssumptionWorklist, renderAssumptionsMd, parseAssumptionResults, renderAssumptionMap, unenforced, LEADS_FILE } from "../assumptions.js";

// `ultrasec assumptions --run <dir> [--repo <dir>]`             → emit the unit worklist
// `ultrasec assumptions --apply <file|dir|a,b,c> --run <dir>`   → write the map + the leads
//
// Runs BEFORE hunting, on the repo rather than the findings: its output is
// understanding, not verdicts. Nothing here changes a finding's status — an
// unenforced assumption is a place to look, and filing "this is unverified" as a
// vulnerability is exactly the padding the severity rubric exists to prevent.
export function runAssumptions(args: ParsedArgs): number {
  const run = resolve(flagStr(args, "run") ?? ".ultrasec");
  let dossier: ReturnType<typeof loadDossier>;
  try {
    dossier = loadDossier(run);
  } catch (e) {
    eprintln(`ultrasec assumptions: ${(e as Error).message}`);
    return 2;
  }
  const repo = resolve(flagStr(args, "repo") ?? dossier.manifest.repo);

  const applyPath = flagStr(args, "apply");
  if (applyPath) {
    let parsed: ReturnType<typeof parseAssumptionResults>;
    try {
      parsed = readApply(applyPath, /assumption.*\.json$/i, parseAssumptionResults);
    } catch (e) {
      eprintln(`ultrasec assumptions: cannot read assumption results at ${(e as Error).message}`);
      return 2;
    }
    const strict = flagBool(args, "strict");
    const leads = unenforced(parsed.rows);

    const mapPath = join(run, "ASSUMPTIONS.md");
    writeFileSync(mapPath, renderAssumptionMap(parsed.rows));
    // Picked up by `investigate` on its next emit and folded into the region
    // prompts — a lead is a question to carry into the hunt, not a finding.
    const leadsPath = join(run, LEADS_FILE);
    writeFileSync(leadsPath, JSON.stringify(leads, null, 2));

    if (flagBool(args, "json")) {
      println(JSON.stringify({ units: parsed.rows.length, unenforced: leads.length, map: mapPath, leads: leadsPath, dropped: parsed.dropped }, null, 2));
      return strict && parsed.dropped.length > 0 ? 1 : 0;
    }
    println(`ultrasec assumptions --apply → ${mapPath}`);
    println(`  ${parsed.rows.length} unit(s) recorded · ${leads.length} assumption(s) nothing enforces`);
    if (leads.length) {
      println(`  leads → ${leadsPath} (folded into the next \`investigate\` emit)`);
      for (const l of leads.slice(0, 8)) println(`    · ${l.at} — ${l.claim}`);
      if (leads.length > 8) println(`    … and ${leads.length - 8} more`);
    } else {
      println(`  nothing unenforced was recorded — either the code checks what it relies on, or the pass was shallow.`);
    }
    return surfaceDropped(parsed.dropped, strict, println);
  }

  const scan = scanRepo(repo, {
    scope: listFlag(args, "scope"),
    include: listFlag(args, "include"),
    exclude: listFlag(args, "exclude"),
    maxFiles: numFlag(args, "max-files"),
    gitignore: flagBool(args, "gitignore"),
  });
  const items = buildAssumptionWorklist(scan);
  const todoPath = emitWorklist(run, stageFiles("ASSUMPTIONS"), items, renderAssumptionsMd(items, loadContextDoc(run)));

  if (flagBool(args, "json")) {
    println(JSON.stringify(items, null, 2));
    return 0;
  }
  println(`ultrasec assumptions → ${todoPath} (${items.length} unit${items.length === 1 ? "" : "s"})`);
  if (!items.length) {
    println(`  no unit reads untrusted input or performs a dangerous operation — check the scan scope.`);
  } else {
    println(`  record what each unit guarantees and what it assumes; mark an unenforced one \`nothing-found\`, then:`);
    println(`  ultrasec assumptions --apply ASSUMPTIONS.json --run ${run}`);
  }
  return 0;
}
