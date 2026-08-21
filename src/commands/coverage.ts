import { writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { flagStr, flagBool, own, println, eprintln, type ParsedArgs } from "../util.js";
import { loadDossier } from "../store.js";
import { buildCoverage, renderCoverageMd, enumeratedKindsOf, STANDARDS, DEFAULT_STANDARD } from "../coverage.js";

// `ultrasec coverage --run <dir> [--standard asvs|owasp-top10|owasp-api-top10|masvs|cwe-top25]`
//
// The honest complement to "only report what you can exploit": a short report
// reads as "nothing there" when it means "nothing there, in what I looked at".
// Read-only — writes COVERAGE.md only with --write.
export function runCoverage(args: ParsedArgs): number {
  const run = resolve(flagStr(args, "run") ?? ".ultrasec");

  // Which standard to score against. own() guards a `--standard constructor`-style
  // prototype-member name; an unrecognized name is an ERROR, not a silent fall-back
  // to ASVS — asking for `owasp-top-10` and quietly getting the ASVS matrix is how a
  // compliance claim goes wrong without anyone noticing (mirrors `scan --budget`).
  const standardId = flagStr(args, "standard") ?? DEFAULT_STANDARD;
  if (!own(STANDARDS, standardId)) {
    eprintln(`ultrasec coverage: unknown --standard '${standardId}' (expected ${Object.keys(STANDARDS).join("|")}).`);
    return 2;
  }

  let dossier: ReturnType<typeof loadDossier>;
  try {
    dossier = loadDossier(run);
  } catch (e) {
    eprintln(`ultrasec coverage: ${(e as Error).message}`);
    return 2;
  }

  // What this run actually enumerated: every category, sink kind and CWE the
  // findings carry. A class the engine covers but the repo never exercised still
  // counts as walked — the pass ran, it simply found nothing.
  const enumerated = enumeratedKindsOf(dossier.findings);
  const rows = buildCoverage(dossier, enumerated, standardId);
  const md = renderCoverageMd(rows, STANDARDS[standardId]!.title, dossier);

  if (flagBool(args, "json")) {
    println(JSON.stringify(rows, null, 2));
    return 0;
  }
  if (flagBool(args, "write")) {
    const p = join(run, "COVERAGE.md");
    writeFileSync(p, md);
    println(`ultrasec coverage → ${p}`);
  }
  println(md);
  const gaps = rows.filter((r) => r.state === "unexamined").length;
  const judgment = rows.filter((r) => r.judgment && r.state !== "examined").length;
  println(`${gaps} categor${gaps === 1 ? "y" : "ies"} not examined · ${judgment} needing an explicit answer.`);
  return 0;
}
