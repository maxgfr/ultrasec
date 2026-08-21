import { join, resolve } from "node:path";
import { flagStr, flagBool, println, eprintln, type ParsedArgs } from "../util.js";
import { loadDossier } from "../store.js";
import { emitWorklist, readApply, persistFindings, stageFiles } from "../stage.js";
import { surfaceDropped } from "../apply-parse.js";
import { buildWorklist, renderWorklistMd, shard, applyVerdicts, parseVerdicts, worklistCounts } from "../verify.js";
import { loadContextDoc } from "../context.js";

// `ultrasec verify --run <dir> [--shards n --shard i]`  → emit the worklist
// `ultrasec verify --apply <file|dir|a,b,c> --run <dir>` → fold verdicts back in
export function runVerify(args: ParsedArgs): number {
  const run = resolve(flagStr(args, "run") ?? ".ultrasec");
  let dossier: ReturnType<typeof loadDossier>;
  try {
    dossier = loadDossier(run);
  } catch (e) {
    eprintln(`ultrasec verify: ${(e as Error).message}`);
    return 2;
  }

  const applyPath = flagStr(args, "apply");
  if (applyPath) return applyMode(run, dossier, applyPath, args);

  // Emit mode
  const all = flagBool(args, "all");
  const counts = worklistCounts(dossier, { all });
  let items = buildWorklist(dossier, { all });
  const shards = Number(flagStr(args, "shards") ?? "0") || 0;
  const shardIdx = Number(flagStr(args, "shard") ?? "0") || 0;
  if (shards > 1) items = shard(items, shards, shardIdx);

  // The MD brief always reflects the FULL worklist; only the JSON todo is sharded.
  // CONTEXT.md (if authored) is injected into the brief — presence-gated, so a run
  // without one is byte-identical to today (guarded by verify-snapshot.test.ts).
  const files = shards > 1 ? { todo: `VERIFY.todo.${shardIdx}.json`, md: "VERIFY.md" } : stageFiles("VERIFY");
  const todoPath = emitWorklist(run, files, items, renderWorklistMd(buildWorklist(dossier, { all }), loadContextDoc(run), counts));

  if (flagBool(args, "json")) {
    println(JSON.stringify(items, null, 2));
    return 0;
  }
  println(`ultrasec verify → ${todoPath} (${items.length} item${items.length === 1 ? "" : "s"}${shards > 1 ? `, shard ${shardIdx}/${shards}` : ""})`);
  // Name what was withheld and the flag that would show it — the `clean --all`
  // shape. Silence here is what let a "delta" batch re-verdict everything.
  if (counts.withheld) println(`  ${counts.fresh} new · ${counts.withheld} already adjudicated as needs-human, not shown — pass --all to re-open them`);
  else if (counts.reOpened) println(`  ${counts.fresh} new · ${counts.reOpened} re-opened (--all)`);
  println(`  adjudicate each (\`ultrasec dossier <id> --run ${run}\`), save verdicts.json, then:`);
  println(`  ultrasec verify --apply verdicts.json --run ${run}`);
  return 0;
}

function applyMode(run: string, dossier: ReturnType<typeof loadDossier>, applyPath: string, args: ParsedArgs): number {
  let parsed: ReturnType<typeof parseVerdicts>;
  try {
    parsed = readApply(applyPath, /verdict.*\.json$/i, parseVerdicts);
  } catch (e) {
    eprintln(`ultrasec verify: cannot read verdicts at ${(e as Error).message}`);
    return 2;
  }
  const strict = flagBool(args, "strict");
  const reVerdictOk = flagBool(args, "re-verdict");

  const res = applyVerdicts(dossier, parsed.rows);
  // Fail closed on an entirely stale fragment: every verdict targeting an
  // unknown id means the fold never engaged — exiting green would silently
  // discard the whole adjudication.
  if (res.applied === 0 && res.ignored.length > 0) {
    eprintln(
      `ultrasec verify --apply: all ${res.ignored.length} verdict(s) target unknown ids (${res.ignored.join(", ")}) — stale fragment? Re-emit the worklist and re-adjudicate; nothing was folded.`,
    );
    return 2;
  }
  persistFindings(run, dossier, res.findings);

  if (flagBool(args, "json")) {
    println(
      JSON.stringify(
        {
          applied: res.applied,
          confirmed: res.confirmed,
          dismissed: res.dismissed,
          needsHuman: res.needsHuman,
          keptForHuman: res.keptForHuman,
          ignored: res.ignored,
          reVerdicted: res.reVerdicted,
          dropped: parsed.dropped,
        },
        null,
        2,
      ),
    );
    return strict && (parsed.dropped.length > 0 || (res.reVerdicted.length > 0 && !reVerdictOk)) ? 1 : 0;
  }
  println(`ultrasec verify --apply → updated ${join(run, "findings.json")}`);
  println(`  applied ${res.applied} verdict(s): ${res.confirmed} confirmed · ${res.dismissed} dismissed · ${res.needsHuman} needs-human`);
  if (res.ignored.length) println(`  ${res.ignored.length} verdict(s) ignored (unknown id): ${res.ignored.join(", ")}`);
  if (res.keptForHuman.length) {
    println(`  kept for human (high-severity, only 'unsupported' — not auto-dismissed):`);
    for (const k of res.keptForHuman) println(`    - ${k.id} [${k.severity}]`);
  }
  // Never let a batch re-decide already-argued findings in silence. Reported
  // always; under --strict it also fails, so CI cannot rubber-stamp it.
  if (res.reVerdicted.length) {
    println(`  ⚠ ${res.reVerdicted.length} verdict(s) CHANGED an already-adjudicated finding:`);
    for (const r of res.reVerdicted.slice(0, 10)) println(`    - ${r.id} [${r.wasStatus}] ${r.from ?? "(none)"} → ${r.to}`);
    if (res.reVerdicted.length > 10) println(`    … and ${res.reVerdicted.length - 10} more`);
    println(`    Re-verifying an escalation is legitimate; doing it by accident is not. Pass --re-verdict to accept under --strict.`);
  }
  if (strict && res.reVerdicted.length > 0 && !reVerdictOk) {
    eprintln(
      `ultrasec verify --apply: ${res.reVerdicted.length} already-adjudicated finding(s) re-verdicted under --strict — pass --re-verdict if that is intended.`,
    );
    return 1;
  }
  return surfaceDropped(parsed.dropped, strict, println);
}
