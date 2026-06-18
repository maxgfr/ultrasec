import { resolve } from "node:path";
import { flagStr, println, eprintln, type ParsedArgs } from "../util.js";
import { loadDossier } from "../store.js";
import { renderFindingDossier } from "../dossier.js";
import { loadContextDoc } from "../context.js";

// `ultrasec dossier <finding-id> [--run .ultrasec] [--repo <dir>]`
// Print the grounding packet (real code + cross-file path + neighbours) for one
// finding — the evidence an adjudicating subagent reads.
export function runDossier(args: ParsedArgs): number {
  const run = resolve(flagStr(args, "run") ?? ".ultrasec");
  const id = args._[1];
  if (!id) {
    eprintln("ultrasec dossier: need a <finding-id>. List them in DOSSIER.md or with `paths`.");
    return 2;
  }

  let d;
  try {
    d = loadDossier(run);
  } catch (e) {
    eprintln(`ultrasec dossier: ${(e as Error).message}`);
    return 2;
  }

  const f = d.findings.find((x) => x.id === id || x.id.startsWith(id));
  if (!f) {
    eprintln(`ultrasec dossier: no finding "${id}" in ${run}.`);
    return 2;
  }

  const repo = flagStr(args, "repo") ?? d.manifest.repo;
  println(renderFindingDossier(repo, d.graph, f, loadContextDoc(run)));
  return 0;
}
