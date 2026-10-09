import { join, resolve } from "node:path";
import { flagStr, flagBool, linesCapped, listCapped, println, eprintln, type ParsedArgs } from "../util.js";
import { loadDossier } from "../store.js";
import { emitWorklist, readApply, persistFindings, stageFiles, wantsMdTwin, worklistNote } from "../stage.js";
import { surfaceDropped } from "../apply-parse.js";
import { buildWorklist, renderWorklistMd, shard, applyVerdicts, parseVerdicts, worklistCounts } from "../verify.js";
import { loadContextDoc } from "../context.js";
import { ADJUDICATION_SURFACE, inSurface, parseSurfaceFlag, SURFACE_FILTERS } from "../surface.js";

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

  // Emit mode. `--surface` narrows the WORKLIST only (default `code+supply`);
  // the fold above takes none — a verdict file names its ids and folds exactly those.
  const surfaceFlag = flagStr(args, "surface");
  const surface = parseSurfaceFlag(surfaceFlag, ADJUDICATION_SURFACE);
  if (surface === null) {
    eprintln(`ultrasec verify: unknown --surface "${surfaceFlag}" — expected one of: ${SURFACE_FILTERS.join(", ")}.`);
    return 2;
  }
  const all = flagBool(args, "all");
  const counts = worklistCounts(dossier, { all, surface });
  let items = buildWorklist(dossier, { all, surface });
  const shards = Number(flagStr(args, "shards") ?? "0") || 0;
  const shardIdx = Number(flagStr(args, "shard") ?? "0") || 0;
  if (shards > 1) items = shard(items, shards, shardIdx);

  // The MD brief (opt-in, `--md`) always reflects the FULL worklist; only the JSON todo is sharded.
  // CONTEXT.md (if authored) is injected into the brief — presence-gated, so a run
  // without one is byte-identical to today (guarded by verify-snapshot.test.ts).
  const files = shards > 1 ? { todo: `VERIFY.todo.${shardIdx}.json`, md: "VERIFY.md" } : stageFiles("VERIFY");
  const wroteMd = wantsMdTwin(args);
  const todoPath = emitWorklist(run, files, items, () => renderWorklistMd(buildWorklist(dossier, { all, surface }), loadContextDoc(run), counts), {
    md: wroteMd,
  });

  const outside = dossier.findings.filter((f) => (f.status === "open" || f.status === "needs-human") && !inSurface(f, surface)).length;
  // The worklist is on disk; `--json` reports where and how much rather than
  // printing it a second time.
  if (flagBool(args, "json")) {
    println(JSON.stringify({ todo: todoPath, items: items.length, counts: { ...counts, outsideSurface: outside, surface } }));
    return 0;
  }
  println(`ultrasec verify → ${todoPath} (${items.length} item${items.length === 1 ? "" : "s"}${shards > 1 ? `, shard ${shardIdx}/${shards}` : ""})`);
  println(worklistNote(files, wroteMd));
  // Name what was withheld and the flag that would show it — the `clean --all`
  // shape. Silence here is what let a "delta" batch re-verdict everything.
  if (counts.withheld) println(`  ${counts.fresh} new · ${counts.withheld} already adjudicated as needs-human, not shown — pass --all to re-open them`);
  else if (counts.reOpened) println(`  ${counts.fresh} new · ${counts.reOpened} re-opened (--all)`);
  if (outside)
    println(
      `  ${outside} pending finding(s) outside --surface ${surface}${surface === ADJUDICATION_SURFACE ? " (dependency advisories: the report ranks them per package)" : ""} — --surface all to include them`,
    );
  println(
    `  adjudicate each (\`ultrasec dossier <id> --run ${run}\`) and write rows {id, verdict, note} — exploitPath on supported, brocard on refuted — to verdicts.json, then:`,
  );
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
      `ultrasec verify --apply: all ${res.ignored.length} verdict(s) target unknown ids (${listCapped("", res.ignored)}) — stale fragment? Re-emit the worklist and re-adjudicate; nothing was folded.`,
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
  if (res.ignored.length) println(`  ${listCapped(`${res.ignored.length} verdict(s) ignored (unknown id)`, res.ignored)}`);
  if (res.keptForHuman.length)
    println(
      `  ${listCapped(
        `${res.keptForHuman.length} kept for human (high-severity, only 'unsupported' — not auto-dismissed)`,
        res.keptForHuman.map((k) => `${k.id} [${k.severity}]`),
      )}`,
    );
  // Never let a batch re-decide already-argued findings in silence. Reported
  // always; under --strict it also fails, so CI cannot rubber-stamp it.
  if (res.reVerdicted.length) {
    println(`  ⚠ ${res.reVerdicted.length} verdict(s) CHANGED an already-adjudicated finding:`);
    for (const line of linesCapped(res.reVerdicted.map((r) => `    - ${r.id} [${r.wasStatus}] ${r.from ?? "(none)"} → ${r.to}`))) println(line);
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
