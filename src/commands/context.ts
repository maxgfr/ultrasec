import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { flagStr, flagBool, listFlag, numFlag, println, eprintln, type ParsedArgs } from "../util.js";
import { scanRepo } from "../scan.js";
import { buildAttackSurface } from "../map.js";
import { buildContextScaffold, renderContextScaffoldMd } from "../context.js";

// `ultrasec context --repo <dir> [--out .ultrasec] [--scope <glob>] [--json]`
// The project-context primer: emit a deterministic scaffold (CONTEXT.scaffold.json)
// + a brief (CONTEXT.todo.md). The agent then authors CONTEXT.md, which ultrasec
// injects into the dossier + verify worklist for every later stage. No `--apply`:
// CONTEXT.md is the agent's free-form prose, additive evidence only.
export function runContext(args: ParsedArgs): number {
  const repo = resolve(flagStr(args, "repo") ?? ".");
  const out = resolve(flagStr(args, "out") ?? ".ultrasec");

  const scanOpts = {
    scope: listFlag(args, "scope"),
    include: listFlag(args, "include"),
    exclude: listFlag(args, "exclude"),
    maxFiles: numFlag(args, "max-files"),
    gitignore: flagBool(args, "gitignore"),
  };

  let scaffold: ReturnType<typeof buildContextScaffold>;
  try {
    const scan = scanRepo(repo, scanOpts);
    const surface = buildAttackSurface(scan);
    scaffold = buildContextScaffold(repo, scan, surface);
  } catch (e) {
    eprintln(`ultrasec context: ${(e as Error).message}`);
    return 2;
  }

  mkdirSync(out, { recursive: true });
  writeFileSync(join(out, "CONTEXT.scaffold.json"), JSON.stringify(scaffold, null, 2));
  writeFileSync(join(out, "CONTEXT.todo.md"), renderContextScaffoldMd(repo, out, scaffold));

  if (flagBool(args, "json")) {
    println(JSON.stringify(scaffold, null, 2));
    return 0;
  }
  println(`ultrasec context → ${out}`);
  println(`  ${join(out, "CONTEXT.scaffold.json")}  ·  ${join(out, "CONTEXT.todo.md")}`);
  println(
    `  frameworks: ${scaffold.frameworks.join(", ") || "—"}  ·  entry points: ${scaffold.entryPoints.length}  ·  auth sites: ${scaffold.authMiddleware.length}  ·  sanitizers: ${scaffold.sanitizers.length}`,
  );
  println(`  next: author ${join(out, "CONTEXT.md")} (see CONTEXT.todo.md), then run \`scan\`/\`verify\` — it's injected into every dossier.`);
  return 0;
}
