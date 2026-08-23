import { resolve } from "node:path";
import { flagBool, flagStr, println, eprintln, type ParsedArgs } from "../util.js";
import { loadDossier } from "../store.js";
import { renderFindingDossier } from "../dossier.js";
import { compactContextDoc, loadContextDoc } from "../context.js";

// `ultrasec dossier <finding-id> [--run .ultrasec] [--repo <dir>] [--compact|--no-context] [--brief]`
// Print the grounding packet (real code + cross-file path + neighbours) for one
// finding — the evidence an adjudicating subagent reads.
export function runDossier(args: ParsedArgs): number {
  const run = resolve(flagStr(args, "run") ?? ".ultrasec");
  const id = args._[1];
  if (!id) {
    eprintln("ultrasec dossier: need a <finding-id>. List them in DOSSIER.md or with `paths`.");
    return 2;
  }

  let d: ReturnType<typeof loadDossier>;
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
  // Serial adjudication is the normal way this command is used — dozens of
  // invocations in a row — and reprinting the whole trust model each time buries
  // the path and the code being scrolled for. `--no-context` drops it outright;
  // `--compact` keeps the sections that bear on reachability and severity.
  //
  // Deliberately NOT "print it once per session": `dossier` is in
  // READ_ONLY_COMMANDS so a fan-out subagent stays a non-writer, and remembering
  // across invocations would need a marker file in the run dir.
  const context = flagBool(args, "no-context") ? undefined : loadContextDoc(run);
  const shown = context && flagBool(args, "compact") ? (compactContextDoc(context) ?? context) : context;
  // `--brief` is the batch packet: narrow windows, no enclosing bodies, no
  // reachability block. One subagent reading eight findings pays for the full
  // depth eight times; one auditor deciding a single flow wants all of it.
  println(renderFindingDossier(repo, d.graph, f, { context: shown, brief: flagBool(args, "brief") }));
  return 0;
}
