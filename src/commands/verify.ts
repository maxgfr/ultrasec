import { readFileSync, writeFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { flagStr, flagBool, println, eprintln, type ParsedArgs } from "../util.js";
import { loadDossier, writeDossier, countBySeverity } from "../store.js";
import { buildWorklist, renderWorklistMd, shard, applyVerdicts, parseVerdicts, type VerdictInput } from "../verify.js";

// `ultrasec verify --run <dir> [--shards n --shard i]`  → emit the worklist
// `ultrasec verify --apply <file|dir|a,b,c> --run <dir>` → fold verdicts back in
export function runVerify(args: ParsedArgs): number {
  const run = resolve(flagStr(args, "run") ?? ".ultrasec");
  let dossier;
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

  const todoName = shards > 1 ? `VERIFY.todo.${shardIdx}.json` : "VERIFY.todo.json";
  writeFileSync(join(run, todoName), JSON.stringify(items, null, 2));
  writeFileSync(join(run, "VERIFY.md"), renderWorklistMd(buildWorklist(dossier)));

  if (flagBool(args, "json")) {
    println(JSON.stringify(items, null, 2));
    return 0;
  }
  println(`ultrasec verify → ${join(run, todoName)} (${items.length} item${items.length === 1 ? "" : "s"}${shards > 1 ? `, shard ${shardIdx}/${shards}` : ""})`);
  println(`  adjudicate each (\`ultrasec dossier <id> --run ${run}\`), save verdicts.json, then:`);
  println(`  ultrasec verify --apply verdicts.json --run ${run}`);
  return 0;
}

function collectVerdictFiles(applyPath: string): string[] {
  // a directory → every *verdict*.json in it; a comma list → each; else one file
  if (applyPath.includes(",")) return applyPath.split(",").map((s) => resolve(s.trim()));
  const abs = resolve(applyPath);
  try {
    if (statSync(abs).isDirectory()) {
      return readdirSync(abs)
        .filter((n) => /verdict.*\.json$/i.test(n))
        .map((n) => join(abs, n));
    }
  } catch {
    /* fall through to single-file */
  }
  return [abs];
}

function applyMode(run: string, dossier: ReturnType<typeof loadDossier>, applyPath: string, args: ParsedArgs): number {
  const files = collectVerdictFiles(applyPath);
  const verdicts: VerdictInput[] = [];
  for (const f of files) {
    try {
      verdicts.push(...parseVerdicts(readFileSync(f, "utf8")));
    } catch (e) {
      eprintln(`ultrasec verify: cannot read verdicts at ${f}: ${(e as Error).message}`);
      return 2;
    }
  }

  const res = applyVerdicts(dossier, verdicts);
  const manifest = { ...dossier.manifest, counts: { findings: res.findings.length, bySeverity: countBySeverity(res.findings) } };
  writeDossier(run, { manifest, findings: res.findings, graph: dossier.graph });

  if (flagBool(args, "json")) {
    println(JSON.stringify({ applied: res.applied, confirmed: res.confirmed, dismissed: res.dismissed, needsHuman: res.needsHuman, keptForHuman: res.keptForHuman }, null, 2));
    return 0;
  }
  println(`ultrasec verify --apply → updated ${run}/findings.json`);
  println(`  applied ${res.applied} verdict(s): ${res.confirmed} confirmed · ${res.dismissed} dismissed · ${res.needsHuman} needs-human`);
  if (res.keptForHuman.length) {
    println(`  kept for human (high-severity, only 'unsupported' — not auto-dismissed):`);
    for (const k of res.keptForHuman) println(`    - ${k.id} [${k.severity}]`);
  }
  return 0;
}
