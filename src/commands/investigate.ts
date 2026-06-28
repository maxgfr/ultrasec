import { resolve } from "node:path";
import { flagStr, flagBool, listFlag, numFlag, println, eprintln, type ParsedArgs } from "../util.js";
import { loadDossier } from "../store.js";
import { emitWorklist, readApply, persistFindings, stageFiles } from "../stage.js";
import { loadContextDoc } from "../context.js";
import { scanRepo } from "../scan.js";
import { buildAttackSurface } from "../map.js";
import { buildInvestigateWorklist, renderInvestigateMd, ingestDiscoveries, parseDiscoveries } from "../investigate.js";

// `ultrasec investigate --run <dir> [--repo <dir>]`             → emit region worklist
// `ultrasec investigate --apply <file|dir|a,b,c> --run <dir>`   → ingest discoveries
// The agentic-discovery stage: the agent finds what the deterministic engine
// can't (authz/IDOR, business logic, multi-hop), and the engine ingests grounded
// Discovery[] as `ultrasec-ai` open candidates (dedup-folded, citation-checked).
export function runInvestigate(args: ParsedArgs): number {
  const run = resolve(flagStr(args, "run") ?? ".ultrasec");
  let dossier: ReturnType<typeof loadDossier>;
  try {
    dossier = loadDossier(run);
  } catch (e) {
    eprintln(`ultrasec investigate: ${(e as Error).message}`);
    return 2;
  }
  const repo = resolve(flagStr(args, "repo") ?? dossier.manifest.repo);

  const applyPath = flagStr(args, "apply");
  if (applyPath) {
    let discoveries: ReturnType<typeof parseDiscoveries>;
    try {
      discoveries = readApply(applyPath, /(investigat|discover).*\.json$/i, parseDiscoveries);
    } catch (e) {
      eprintln(`ultrasec investigate: cannot read discoveries at ${(e as Error).message}`);
      return 2;
    }
    const res = ingestDiscoveries(dossier, discoveries, repo);
    persistFindings(run, dossier, res.findings);

    if (flagBool(args, "json")) {
      println(
        JSON.stringify(
          { ingested: res.ingested, folded: res.folded, rejected: res.rejected.map((r) => ({ title: r.discovery.title, reason: r.reason })) },
          null,
          2,
        ),
      );
      return 0;
    }
    println(`ultrasec investigate --apply → updated ${run}/findings.json`);
    println(`  ingested ${res.ingested} new ${"ultrasec-ai"} finding(s) · folded ${res.folded} into existing · rejected ${res.rejected.length}`);
    for (const r of res.rejected) println(`  ✗ rejected "${r.discovery.title}": ${r.reason}`);
    if (res.ingested) println(`  next: \`ultrasec dossier <id> --run ${run}\` then \`verify\` — adjudicate them like any candidate.`);
    return 0;
  }

  // Emit mode
  const scanOpts = {
    scope: listFlag(args, "scope"),
    include: listFlag(args, "include"),
    exclude: listFlag(args, "exclude"),
    maxFiles: numFlag(args, "max-files"),
    gitignore: flagBool(args, "gitignore"),
  };
  let regions: ReturnType<typeof buildInvestigateWorklist>;
  try {
    regions = buildInvestigateWorklist(buildAttackSurface(scanRepo(repo, scanOpts)), dossier.graph);
  } catch (e) {
    eprintln(`ultrasec investigate: ${(e as Error).message}`);
    return 2;
  }
  const todoPath = emitWorklist(run, stageFiles("INVESTIGATE"), regions, renderInvestigateMd(regions, loadContextDoc(run)));

  if (flagBool(args, "json")) {
    println(JSON.stringify(regions, null, 2));
    return 0;
  }
  println(`ultrasec investigate → ${todoPath} (${regions.length} region${regions.length === 1 ? "" : "s"})`);
  if (!regions.length) {
    println(`  no attack-surface regions detected — try \`map\` or widen the scope.`);
  } else {
    println(`  investigate each region, emit grounded Discovery[] as INVESTIGATE.json, then:`);
    println(`  ultrasec investigate --apply INVESTIGATE.json --run ${run}`);
  }
  return 0;
}
