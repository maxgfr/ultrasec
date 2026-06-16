import { resolve } from "node:path";
import { flagStr, flagBool, println, eprintln, type ParsedArgs } from "../util.js";
import { loadDossier } from "../store.js";
import { check } from "../check.js";
import { SEVERITIES, type Severity } from "../types.js";

// `ultrasec check --run <dir> [--semantic] [--min-severity <s>]`
// Exit non-zero when a cited [file:line] doesn't resolve (anti-hallucination),
// and — with --semantic — when candidates remain unadjudicated.
export function runCheck(args: ParsedArgs): number {
  const run = resolve(flagStr(args, "run") ?? ".ultrasec");
  const repo = flagStr(args, "repo");
  const semantic = flagBool(args, "semantic");
  const minSevRaw = flagStr(args, "min-severity");
  const minSeverity = minSevRaw && (SEVERITIES as readonly string[]).includes(minSevRaw) ? (minSevRaw as Severity) : undefined;

  let dossier;
  try {
    dossier = loadDossier(run);
  } catch (e) {
    eprintln(`ultrasec check: ${(e as Error).message}`);
    return 2;
  }

  const res = check(dossier, { repo, semantic, minSeverity });

  if (flagBool(args, "json")) {
    println(JSON.stringify(res, null, 2));
    return res.ok ? 0 : 1;
  }

  for (const d of res.dangling.slice(0, 50)) {
    eprintln(`  ✗ ${d.id}: ${d.file}:${d.line} — ${d.reason}`);
  }
  for (const m of res.messages) println((res.ok ? "  ✓ " : "  • ") + m);
  return res.ok ? 0 : 1;
}
