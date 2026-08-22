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
  // An unrecognized name is an ERROR, not a silent fall-back to "gate on
  // everything" — asking for `--min-severity hgih` and quietly getting a WIDER
  // gate than you asked for inverts the flag's meaning, and a gate that passes
  // for the wrong reason is worse than one that fails. `--budget` fails closed
  // for the same reason (src/commands/scan.ts).
  const minSevRaw = flagStr(args, "min-severity");
  if (minSevRaw !== undefined && !(SEVERITIES as readonly string[]).includes(minSevRaw)) {
    eprintln(`ultrasec: unknown --min-severity '${minSevRaw}' (expected ${SEVERITIES.join("|")}).`);
    return 2;
  }
  const minSeverity = minSevRaw as Severity | undefined;

  let dossier: ReturnType<typeof loadDossier>;
  try {
    dossier = loadDossier(run);
  } catch (e) {
    eprintln(`ultrasec check: ${(e as Error).message}`);
    return 2;
  }

  // `run` is passed so the gate can read the agent-authored CONTEXT.md and
  // confront its negations with the tree. Absent CONTEXT.md ⇒ nothing changes.
  const res = check(dossier, { repo, semantic, minSeverity, run });

  if (flagBool(args, "json")) {
    println(JSON.stringify(res, null, 2));
    return res.ok ? 0 : 1;
  }

  for (const d of res.dangling.slice(0, 50)) {
    eprintln(`  ✗ ${d.id}: ${d.file}:${d.line} — ${d.reason}`);
  }
  // Contradicted negations print under their own marker rather than through the
  // message list: a `✓` in front of "CONTEXT.md says there are none and here are
  // seven" reads as approval of exactly the sentence being challenged.
  for (const c of res.contradictions) {
    const where = c.hits.map((h) => `${h.file}:${h.line}`).join(", ");
    const more = c.total > c.hits.length ? ` +${c.total - c.hits.length} more` : "";
    eprintln(`  ⚠️  CONTEXT.md:${c.claim.line} — \`${c.token}\` occurs ${c.total} time(s) in code: ${where}${more}`);
    eprintln(`      “${c.claim.sentence.length <= 110 ? c.claim.sentence : `${c.claim.sentence.slice(0, 107)}…`}”`);
  }
  if (res.contradictions.length && !semantic) {
    eprintln(
      `  ⚠️  ${res.contradictions.length} negation(s) in CONTEXT.md contradicted by the code. Every later stage reads that document as background — reconcile the sentence, or the finding. \`--semantic\` fails on this.`,
    );
  }
  for (const m of res.messages) println((res.ok ? "  ✓ " : "  • ") + m);
  return res.ok ? 0 : 1;
}
