import { join, resolve } from "node:path";
import { flagStr, flagBool, println, eprintln, type ParsedArgs } from "../util.js";
import { loadDossier } from "../store.js";
import { emitWorklist, readApply, persistFindings, stageFiles } from "../stage.js";
import { buildWorklist, renderWorklistMd, shard, applyVerdicts, parseVerdicts } from "../verify.js";
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
  let items = buildWorklist(dossier);
  const shards = Number(flagStr(args, "shards") ?? "0") || 0;
  const shardIdx = Number(flagStr(args, "shard") ?? "0") || 0;
  if (shards > 1) items = shard(items, shards, shardIdx);

  // The MD brief always reflects the FULL worklist; only the JSON todo is sharded.
  // CONTEXT.md (if authored) is injected into the brief — presence-gated, so a run
  // without one is byte-identical to today (guarded by verify-snapshot.test.ts).
  const files = shards > 1 ? { todo: `VERIFY.todo.${shardIdx}.json`, md: "VERIFY.md" } : stageFiles("VERIFY");
  const todoPath = emitWorklist(run, files, items, renderWorklistMd(buildWorklist(dossier), loadContextDoc(run)));

  if (flagBool(args, "json")) {
    println(JSON.stringify(items, null, 2));
    return 0;
  }
  println(`ultrasec verify → ${todoPath} (${items.length} item${items.length === 1 ? "" : "s"}${shards > 1 ? `, shard ${shardIdx}/${shards}` : ""})`);
  println(`  adjudicate each (\`ultrasec dossier <id> --run ${run}\`), save verdicts.json, then:`);
  println(`  ultrasec verify --apply verdicts.json --run ${run}`);
  return 0;
}

function applyMode(run: string, dossier: ReturnType<typeof loadDossier>, applyPath: string, args: ParsedArgs): number {
  let verdicts: ReturnType<typeof parseVerdicts>;
  try {
    verdicts = readApply(applyPath, /verdict.*\.json$/i, parseVerdicts);
  } catch (e) {
    eprintln(`ultrasec verify: cannot read verdicts at ${(e as Error).message}`);
    return 2;
  }

  const res = applyVerdicts(dossier, verdicts);
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
        },
        null,
        2,
      ),
    );
    return 0;
  }
  println(`ultrasec verify --apply → updated ${join(run, "findings.json")}`);
  println(`  applied ${res.applied} verdict(s): ${res.confirmed} confirmed · ${res.dismissed} dismissed · ${res.needsHuman} needs-human`);
  if (res.ignored.length) println(`  ${res.ignored.length} verdict(s) ignored (unknown id): ${res.ignored.join(", ")}`);
  if (res.keptForHuman.length) {
    println(`  kept for human (high-severity, only 'unsupported' — not auto-dismissed):`);
    for (const k of res.keptForHuman) println(`    - ${k.id} [${k.severity}]`);
  }
  return 0;
}
