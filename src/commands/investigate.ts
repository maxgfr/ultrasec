import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { flagStr, flagBool, listFlag, numFlag, println, eprintln, type ParsedArgs } from "../util.js";
import { loadDossier } from "../store.js";
import { emitWorklist, readApply, persistFindings, stageFiles } from "../stage.js";
import { formatNormalized, surfaceDropped } from "../apply-parse.js";
import { loadContextDoc } from "../context.js";
import { scanRepo } from "../scan.js";
import { buildAttackSurface } from "../map.js";
import { buildInvestigateWorklist, renderInvestigateMd, ingestDiscoveries, parseDiscoveries, LENSES } from "../investigate.js";
import { LEADS_FILE } from "../assumptions.js";
import { buildClassHunts, parseHuntResults, recordHuntResults, type HuntResults } from "../classes/hunt.js";
import { PACKS } from "../classes/packs/index.js";

// `ultrasec investigate --run <dir> [--repo <dir>]`             → emit region worklist
// `ultrasec investigate --apply <file|dir|a,b,c> --run <dir>`   → ingest discoveries
//                                                                 (+ class-hunt idioms → PACK-SUGGESTIONS.json)
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
    // The weakness-class half of the same files: idioms and hunted cells.
    const huntResults: HuntResults[] = [];
    try {
      parsed = readApply(applyPath, /(investigat|discover).*\.json$/i, (raw) => {
        const rows = parseDiscoveries(raw);
        huntResults.push(parseHuntResults(raw));
        return rows;
      });
    } catch (e) {
      eprintln(`ultrasec investigate: cannot read discoveries at ${(e as Error).message}`);
      return 2;
    }
    const strict = flagBool(args, "strict");
    const res = ingestDiscoveries(dossier, parsed.rows, repo, { context: loadContextDoc(run) });
    persistFindings(run, dossier, res.findings);
    const idiomDrops = huntResults.flatMap((h) => h.dropped);
    const rec = recordHuntResults(
      run,
      repo,
      dossier.manifest,
      huntResults,
      PACKS.flatMap((p) => (p.framework ? [p.framework] : [])),
    );
    const idiomRefusals = idiomDrops.length + rec.rejected.length;

    if (flagBool(args, "json")) {
      println(
        JSON.stringify(
          {
            ingested: res.ingested,
            folded: res.folded,
            normalized: parsed.normalized ?? [],
            rejected: res.rejected.map((r) => ({ title: r.discovery.title, reason: r.reason })),
            dropped: parsed.dropped,
            idioms: {
              accepted: rec.accepted,
              rejected: rec.rejected.map((r) => ({ pattern: r.idiom.pattern, reason: r.reason })),
              dropped: idiomDrops,
            },
            hunted: rec.hunted,
          },
          null,
          2,
        ),
      );
      return strict && (parsed.dropped.length > 0 || res.rejected.length > 0 || idiomRefusals > 0) ? 1 : 0;
    }
    println(`ultrasec investigate --apply → updated ${run}/findings.json`);
    println(
      `  ingested ${res.ingested} new ${"ultrasec-ai"} finding(s) · folded ${res.folded} into existing · rejected ${res.rejected.length} · dropped ${parsed.dropped.length}`,
    );
    for (const line of formatNormalized(parsed.normalized ?? [])) println(line);
    for (const r of res.rejected) println(`  ✗ rejected "${r.discovery.title}": ${r.reason}`);
    if (rec.path)
      println(
        `  pack suggestions: ${rec.accepted} new idiom(s) · ${rec.hunted.length} hunt(s) recorded → ${rec.path} (proposals — the engine never applies them)`,
      );
    for (const d of idiomDrops) println(`  ✗ dropped ${d.reason}`);
    for (const r of rec.rejected) println(`  ✗ rejected idiom "${r.idiom.pattern.slice(0, 60)}": ${r.reason}`);
    // A citation the repo doesn't have is a refused row exactly like a malformed
    // one — the discovery is gone either way — so `--strict` has to count both.
    // Counting only `dropped` let a schema-valid discovery citing an invented
    // [file:line] exit 0, which is the one case the citation gate exists for.
    if (strict && res.rejected.length > 0)
      println(`  --strict: ${res.rejected.length} discovery(ies) refused by the citation gate — failing so the loss isn't absorbed silently.`);
    if (strict && idiomRefusals > 0) println(`  --strict: ${idiomRefusals} idiom(s) refused — failing so the loss isn't absorbed silently.`);
    const code = surfaceDropped(parsed.dropped, strict, println) || (strict && idiomRefusals > 0 ? 1 : 0);
    // A refused discovery is unrecoverable in a way a refused verdict is not: a
    // verdict left un-applied leaves the finding `open`, and `check --semantic`
    // will not pass until someone rules on it. A dropped discovery becomes a
    // finding that never existed — nothing downstream ever notices. So when most
    // of a batch is refused, say so in those terms rather than leaving it to a
    // count the reader has to compare against the file they submitted.
    const submitted = parsed.rows.length + parsed.dropped.length;
    if (parsed.dropped.length > 0 && parsed.dropped.length * 2 >= submitted)
      println(
        `  ⚠ ${parsed.dropped.length} of ${submitted} discoveries were refused — those findings do NOT exist in the dossier and no later stage will report them missing. Fix the rows above and re-apply.`,
      );
    if (res.ingested) println(`  next: \`ultrasec dossier <id> --run ${run}\` then \`verify\` — adjudicate them like any candidate.`);
    return code || (strict && res.rejected.length > 0 ? 1 : 0);
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
    const surface = buildAttackSurface(scanRepo(repo, scanOpts));
    // One hunt per weakness class × framework that no pack settles (no pack,
    // or a version outside its testedWith) — from the scan's coverage matrix.
    regions = buildInvestigateWorklist(surface, dossier.graph, leads, lens, buildClassHunts(dossier.manifest, surface));
  } catch (e) {
    eprintln(`ultrasec investigate: ${(e as Error).message}`);
    return 2;
  }
  const todoPath = emitWorklist(run, stageFiles("INVESTIGATE"), regions, renderInvestigateMd(regions, loadContextDoc(run)));

  if (flagBool(args, "json")) {
    println(JSON.stringify(regions, null, 2));
    return 0;
  }
  const hunts = regions.filter((r) => r.hunt).length;
  const areas = regions.length - hunts;
  println(
    `ultrasec investigate → ${todoPath} (${areas} region${areas === 1 ? "" : "s"}${hunts ? ` · ${hunts} weakness-class hunt${hunts === 1 ? "" : "s"}` : ""})`,
  );
  if (!regions.length) {
    println(`  no attack-surface regions detected — try \`map\` or widen the scope.`);
  } else {
    println(`  investigate each region, emit grounded Discovery[] as INVESTIGATE.json, then:`);
    println(`  ultrasec investigate --apply INVESTIGATE.json --run ${run}`);
  }
  return 0;
}
