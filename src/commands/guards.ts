import { resolve } from "node:path";
import { flagStr, flagBool, println, eprintln, type ParsedArgs } from "../util.js";
import { loadDossier, writeDossier } from "../store.js";
import { scanRepo } from "../scan.js";
import { buildGuardMatrix, guardDiscovery, guardTotals, parseGuardVerdicts, renderGuardsMd, type GuardInput, type GuardRow } from "../guards.js";
import { ingestDiscoveries } from "../investigate.js";
import { loadContextDoc } from "../context.js";
import { emitWorklist, stageFiles, readApply, persistFindings } from "../stage.js";
import { surfaceDropped, type ParseResult } from "../apply-parse.js";

// `ultrasec guards --run <dir> [--repo <dir>]`      → GUARDS.md + GUARDS.todo.json
// `ultrasec guards --apply GUARDS.json --run <dir>` → fold the verdicts in
//
// The stage that asks the question a taint pass cannot: which request handlers
// has nobody put an authorization check in front of? See `src/guards.ts` for why
// this exists and what a row does and does not claim.

export function runGuards(args: ParsedArgs): number {
  const run = resolve(flagStr(args, "run") ?? ".ultrasec");
  const strict = flagBool(args, "strict");

  let dossier: ReturnType<typeof loadDossier>;
  try {
    dossier = loadDossier(run);
  } catch (e) {
    eprintln(`ultrasec guards: ${(e as Error).message}`);
    return 2;
  }
  const repo = resolve(flagStr(args, "repo") ?? dossier.manifest.repo);

  const applyPath = flagStr(args, "apply");
  if (applyPath) {
    let parsed: ParseResult<GuardInput>;
    try {
      parsed = readApply(applyPath, /guard.*\.json$/i, parseGuardVerdicts);
    } catch (e) {
      eprintln(`ultrasec guards --apply: ${(e as Error).message}`);
      return 2;
    }

    // Re-derive the matrix rather than trusting the worklist on disk: a verdict
    // must name a handler that exists in the CODE, so a stale or hand-edited
    // GUARDS.json cannot introduce a finding whose citation nobody checked.
    const byId = new Map(buildGuardMatrix(scanRepo(repo)).map((r) => [r.id, r]));
    const unknown: string[] = [];
    const discoveries = [];
    let guarded = 0;
    let publicOnPurpose = 0;
    for (const row of parsed.rows) {
      const at = byId.get(row.id);
      if (!at) {
        unknown.push(row.id);
        continue;
      }
      if (row.verdict === "guarded") guarded++;
      else if (row.verdict === "intentionally-public") publicOnPurpose++;
      else discoveries.push(guardDiscovery(at, row.note));
    }

    const res = ingestDiscoveries(dossier, discoveries, repo, { context: loadContextDoc(run) });
    persistFindings(run, dossier, res.findings);

    println(`ultrasec guards --apply → ${run}`);
    println(
      `  ${res.ingested} unguarded handler(s) filed as findings · ${res.folded} folded into existing · ${guarded} confirmed guarded · ${publicOnPurpose} intentionally public`,
    );
    for (const r of res.rejected) eprintln(`  ✗ rejected ${r.discovery.file}:${r.discovery.line} — ${r.reason}`);
    for (const id of unknown) eprintln(`  ✗ dropped ${id}: no handler with that id in the current matrix (re-run \`ultrasec guards\` and refill)`);
    const code = surfaceDropped(parsed.dropped, strict, eprintln);
    if (strict && (unknown.length || res.rejected.length)) return 1;
    return code;
  }

  const rows: GuardRow[] = buildGuardMatrix(scanRepo(repo));
  const todoPath = emitWorklist(run, stageFiles("GUARDS"), rows, renderGuardsMd(rows, loadContextDoc(run)));
  const t = guardTotals(rows);

  // Record the pass, so `coverage` can stop calling CWE-306/862 "not
  // enumerated". Written on EMIT rather than on apply: the enumeration is what
  // the coverage claim is about, and an unadjudicated `unguarded` row is
  // reported as the open question it is.
  writeDossier(run, { ...dossier, manifest: { ...dossier.manifest, passes: { ...dossier.manifest.passes, guards: true } } });

  println(`ultrasec guards → ${run}`);
  println(
    `  ${t.handlers} handler(s) reading request data · ${t.unguarded} with no visible guard${t.fileScoped ? ` · ${t.fileScoped} file-scoped (weaker evidence)` : ""}`,
  );
  if (!t.handlers) {
    println(`  no HTTP/WS handler found — if the app has routes, check \`manifest.extraction\` and the scan's --scope.`);
  }
  println(`  worklist: ${todoPath}`);
  println(`  next: read GUARDS.md, set a verdict per row, then \`ultrasec guards --apply GUARDS.json --run ${run}\``);
  return 0;
}
