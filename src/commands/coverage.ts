import { writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { flagStr, flagBool, println, eprintln, type ParsedArgs } from "../util.js";
import { loadDossier } from "../store.js";
import { buildCoverage, renderCoverageMd } from "../coverage.js";

// `ultrasec coverage --run <dir>`
//
// The honest complement to "only report what you can exploit": a short report
// reads as "nothing there" when it means "nothing there, in what I looked at".
// Read-only — writes COVERAGE.md only with --write.
export function runCoverage(args: ParsedArgs): number {
  const run = resolve(flagStr(args, "run") ?? ".ultrasec");
  let dossier: ReturnType<typeof loadDossier>;
  try {
    dossier = loadDossier(run);
  } catch (e) {
    eprintln(`ultrasec coverage: ${(e as Error).message}`);
    return 2;
  }

  // What this run actually enumerated: every sink kind and category the findings
  // carry. A class the engine covers but the repo never exercised still counts as
  // walked — the pass ran, it simply found nothing.
  const enumerated = [...new Set(dossier.findings.flatMap((f) => [f.category, f.sink?.kind].filter((x): x is string => Boolean(x))))];
  const rows = buildCoverage(dossier, enumerated);
  const md = renderCoverageMd(rows);

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
