import { resolve, join } from "node:path";
import { mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { flagStr, flagBool, listFlag, numFlag, println, type ParsedArgs } from "../util.js";
import { scanRepo } from "../scan.js";
import { buildAttackSurface, renderMapMd } from "../map.js";

// `ultrasec map --repo <dir> [--scope ...] [--out <run>] [--json]`
// The cheap attack-surface recon command — scan + catalog detection, NO taint BFS
// and NO external tools. Fast even on huge repos; hands the AI a threat-model to
// pick scoped targets from. Writes MAP.md + attack-surface.json additively when
// --out is given (never touches findings/graph/manifest).
export async function runMap(args: ParsedArgs): Promise<number> {
  const repo = resolve(flagStr(args, "repo") ?? ".");
  const out = flagStr(args, "out");
  const scope = listFlag(args, "scope");
  const include = listFlag(args, "include");
  const exclude = listFlag(args, "exclude");
  const maxFiles = numFlag(args, "max-files");
  const gitignore = flagBool(args, "gitignore");

  // Mark targets a prior run already scanned (read manifest.scopes if present).
  let coveredScopes: string[] = [];
  if (out) {
    const mPath = join(resolve(out), "manifest.json");
    if (existsSync(mPath)) {
      try {
        const m = JSON.parse(readFileSync(mPath, "utf8"));
        if (Array.isArray(m.scopes)) coveredScopes = m.scopes;
      } catch {
        /* ignore a malformed/older manifest */
      }
    }
  }

  const scan = scanRepo(repo, { scope, include, exclude, maxFiles, gitignore });
  const surface = buildAttackSurface(scan, coveredScopes);

  if (out) {
    const outDir = resolve(out);
    mkdirSync(outDir, { recursive: true });
    writeFileSync(join(outDir, "attack-surface.json"), JSON.stringify(surface, null, 2));
    writeFileSync(join(outDir, "MAP.md"), renderMapMd(repo, surface));
  }

  if (flagBool(args, "json")) {
    println(JSON.stringify(surface, null, 2));
    return 0;
  }

  println(renderMapMd(repo, surface));
  if (out) println(`\nwrote ${join(resolve(out), "MAP.md")} + attack-surface.json`);
  return 0;
}
