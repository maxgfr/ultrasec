import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { flagStr, flagBool, listFlag, numFlag, println, eprintln, type ParsedArgs } from "../util.js";
import { loadDossier } from "../store.js";
import { emitWorklist, readApply, persistFindings, stageFiles } from "../stage.js";
import { surfaceDropped } from "../apply-parse.js";
import { loadContextDoc } from "../context.js";
import { scanRepo } from "../scan.js";
import { buildAttackSurface } from "../map.js";
import { buildInvestigateWorklist, renderInvestigateMd, ingestDiscoveries, parseDiscoveries, LENSES } from "../investigate.js";
import { LEADS_FILE } from "../assumptions.js";

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
    let parsed: ReturnType<typeof parseDiscoveries>;
    try {
      parsed = readApply(applyPath, /(investigat|discover).*\.json$/i, parseDiscoveries);
    } catch (e) {
      eprintln(`ultrasec investigate: cannot read discoveries at ${(e as Error).message}`);
      return 2;
    }
    const strict = flagBool(args, "strict");
    const res = ingestDiscoveries(dossier, parsed.rows, repo);
    persistFindings(run, dossier, res.findings);

    if (flagBool(args, "json")) {
      println(
        JSON.stringify(
          {
            ingested: res.ingested,
            folded: res.folded,
            rejected: res.rejected.map((r) => ({ title: r.discovery.title, reason: r.reason })),
            dropped: parsed.dropped,
          },
          null,
          2,
        ),
      );
      return strict && parsed.dropped.length > 0 ? 1 : 0;
    }
    println(`ultrasec investigate --apply → updated ${run}/findings.json`);
    println(
      `  ingested ${res.ingested} new ${"ultrasec-ai"} finding(s) · folded ${res.folded} into existing · rejected ${res.rejected.length} · dropped ${parsed.dropped.length}`,
    );
    for (const r of res.rejected) println(`  ✗ rejected "${r.discovery.title}": ${r.reason}`);
    const code = surfaceDropped(parsed.dropped, strict, println);
    if (res.ingested) println(`  next: \`ultrasec dossier <id> --run ${run}\` then \`verify\` — adjudicate them like any candidate.`);
    return code;
  }

  // Emit mode
  const scanOpts = {
    scope: listFlag(args, "scope"),
    include: listFlag(args, "include"),
    exclude: listFlag(args, "exclude"),
    maxFiles: numFlag(args, "max-files"),
    gitignore: flagBool(args, "gitignore"),
  };
  // Leads from `assumptions`, when that stage ran: places the code trusts
  // something nothing verifies. Best-effort — a missing or malformed file simply
  // means no leads, never a failed emit.
  let leads: { at: string; claim: string }[] = [];
  try {
    leads = JSON.parse(readFileSync(join(run, LEADS_FILE), "utf8")) as typeof leads;
    if (!Array.isArray(leads)) leads = [];
  } catch {
    leads = [];
  }

  // A lens changes the QUESTION, not the scope. Fail closed on an unknown name:
  // silently hunting with the default frame when a specific one was asked for is
  // how "no findings" comes to mean "not looked for".
  const lens = flagStr(args, "lens");
  if (lens !== undefined && !Object.hasOwn(LENSES, lens)) {
    eprintln(`ultrasec: unknown --lens '${lens}' (expected ${Object.keys(LENSES).join("|")}).`);
    return 2;
  }

  let regions: ReturnType<typeof buildInvestigateWorklist>;
  try {
    regions = buildInvestigateWorklist(buildAttackSurface(scanRepo(repo, scanOpts)), dossier.graph, leads, lens);
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
