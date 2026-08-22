import { resolve } from "node:path";
import { flagStr, flagBool, println, eprintln, type ParsedArgs } from "../util.js";
import { loadDossier, writeDossier } from "../store.js";
import { scanRepo } from "../scan.js";
import {
  buildGuardMatrix,
  guardDiscovery,
  guardTotals,
  parseGuardVerdicts,
  renderGuardsMd,
  GUARD_LENSES,
  LENSES,
  type GuardInput,
  type GuardLens,
  type GuardRow,
} from "../guards.js";
import { ingestDiscoveries } from "../investigate.js";
import { loadContextDoc } from "../context.js";
import { emitWorklist, stageFiles, readApply, persistFindings } from "../stage.js";
import { surfaceDropped, type ParseResult } from "../apply-parse.js";

// `ultrasec guards --run <dir> [--repo <dir>]`      → GUARDS.md + GUARDS.todo.json
// `ultrasec guards --apply GUARDS.json --run <dir>` → fold the verdicts in
// `ultrasec guards --lens throttle …`               → THROTTLE.md + THROTTLE.todo.json
//
// The stage that asks the questions a taint pass cannot: which request handlers
// has nobody put an authorization check in front of, and which has nobody put a
// rate limit in front of? See `src/guards.ts` for why this exists and what a row
// does and does not claim.

const isLens = (s: string): s is GuardLens => (GUARD_LENSES as readonly string[]).includes(s);

export function runGuards(args: ParsedArgs): number {
  const run = resolve(flagStr(args, "run") ?? ".ultrasec");
  const strict = flagBool(args, "strict");

  // An unrecognized lens is an ERROR, never a silent fall-back to `auth` —
  // asking for `--lens throtle` and quietly auditing authorization instead is
  // how a whole class goes unexamined without anyone noticing. Same failure
  // mode `--budget` fails closed on.
  const lensName = flagStr(args, "lens");
  if (lensName !== undefined && !isLens(lensName)) {
    eprintln(`ultrasec guards: unknown --lens '${lensName}' (expected ${GUARD_LENSES.join("|")}).`);
    return 2;
  }
  const lens: GuardLens = lensName && isLens(lensName) ? lensName : "auth";
  const spec = LENSES[lens];
  const [present, absent, waived] = spec.verdicts;
  const label = lens === "auth" ? "guard" : "rate limit";

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
      parsed = readApply(applyPath, lens === "auth" ? /guard.*\.json$/i : /throttle.*\.json$/i, (raw) => parseGuardVerdicts(raw, lens));
    } catch (e) {
      eprintln(`ultrasec guards --apply: ${(e as Error).message}`);
      return 2;
    }

    // Re-derive the matrix rather than trusting the worklist on disk: a verdict
    // must name a handler that exists in the CODE, so a stale or hand-edited
    // GUARDS.json cannot introduce a finding whose citation nobody checked.
    const byId = new Map(buildGuardMatrix(scanRepo(repo), lens).map((r) => [r.id, r]));
    const unknown: string[] = [];
    const discoveries = [];
    let confirmedPresent = 0;
    let waivedRows = 0;
    for (const row of parsed.rows) {
      const at = byId.get(row.id);
      if (!at) {
        unknown.push(row.id);
        continue;
      }
      if (row.verdict === present) confirmedPresent++;
      else if (row.verdict === waived) waivedRows++;
      else discoveries.push(guardDiscovery(at, row.note, lens));
    }

    const res = ingestDiscoveries(dossier, discoveries, repo, { context: loadContextDoc(run) });
    persistFindings(run, dossier, res.findings);

    println(`ultrasec guards --apply → ${run}`);
    println(
      `  ${res.ingested} ${absent} handler(s) filed as findings · ${res.folded} folded into existing · ${confirmedPresent} confirmed ${present} · ${waivedRows} ${waived}`,
    );
    for (const r of res.rejected) eprintln(`  ✗ rejected ${r.discovery.file}:${r.discovery.line} — ${r.reason}`);
    for (const id of unknown)
      eprintln(
        `  ✗ dropped ${id}: no handler with that id in the current matrix (re-run \`ultrasec guards${lens === "auth" ? "" : " --lens " + lens}\` and refill)`,
      );
    const code = surfaceDropped(parsed.dropped, strict, eprintln);
    if (strict && (unknown.length || res.rejected.length)) return 1;
    return code;
  }

  const rows: GuardRow[] = buildGuardMatrix(scanRepo(repo), lens);
  const todoPath = emitWorklist(run, stageFiles(spec.stem), rows, renderGuardsMd(rows, loadContextDoc(run), lens));
  const t = guardTotals(rows);

  // Record the pass, so `coverage` can stop calling CWE-306/862 (auth) and
  // CWE-407/770 (throttle) "not enumerated". Written on EMIT rather than on
  // apply: the enumeration is what the coverage claim is about, and an
  // unadjudicated row is reported as the open question it is.
  writeDossier(run, { ...dossier, manifest: { ...dossier.manifest, passes: { ...dossier.manifest.passes, [spec.pass]: true } } });

  println(`ultrasec guards${lens === "auth" ? "" : ` --lens ${lens}`} → ${run}`);
  println(
    `  ${t.handlers} handler(s) reading request data · ${t.unguarded} with no visible ${label}${t.fileScoped ? ` · ${t.fileScoped} file-scoped (weaker evidence)` : ""}`,
  );
  if (t.noMarkerAnywhere && lens === "throttle") {
    println(`  ⚠️  NO throttling marker anywhere in the tree — that is one architectural fact, not ${t.handlers} findings.`);
    println(`      Decide once in CONTEXT.md: nothing bounds request volume, or the limit lives outside the repo (ingress/CDN/gateway)?`);
  } else if (t.noMarkerAnywhere) {
    println(`  ⚠️  NO auth marker anywhere in the tree — that is one architectural fact, not ${t.handlers} findings.`);
    println(`      Decide once in CONTEXT.md: public by design, or authenticated outside the repo (gateway/ingress/proxy)?`);
  }
  if (lens === "throttle" && t.unguardedLoginShaped) {
    println(`  ⚠️  ${t.unguardedLoginShaped} of them look like AUTH endpoints — there the absence is credential stuffing (CWE-307)`);
    println(`      and, if a failed login distinguishes an unknown account from a wrong password, enumeration (CWE-204).`);
  }
  if (!t.handlers) {
    println(`  no HTTP/WS handler found — if the app has routes, check \`manifest.extraction\` and the scan's --scope.`);
  }
  println(`  worklist: ${todoPath}`);
  println(
    `  next: read ${spec.stem}.md, set a verdict per row, then \`ultrasec guards${lens === "auth" ? "" : ` --lens ${lens}`} --apply ${spec.stem}.json --run ${run}\``,
  );
  return 0;
}
