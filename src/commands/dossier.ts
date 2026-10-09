import { resolve } from "node:path";
import { flagBool, flagStr, println, eprintln, type ParsedArgs } from "../util.js";
import { loadDossier } from "../store.js";
import { renderFamilyDossier, renderFindingDossier } from "../dossier.js";
import { compactContextDoc, loadContextDoc } from "../context.js";
import type { Finding } from "../types.js";

// `ultrasec dossier <finding-id>[,<id>…] [--run .ultrasec] [--repo <dir>] [--compact|--no-context] [--brief]`
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

  // `a,b,c` is a family: one packet, the first member in full and a window per
  // other member. Every id must resolve — a family with a hole is refused, not
  // shown short.
  const wanted = id
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);
  const found: Finding[] = [];
  for (const w of wanted) {
    const hit = d.findings.find((x) => x.id === w || x.id.startsWith(w));
    if (!hit) {
      eprintln(`ultrasec dossier: no finding "${w}" in ${run}.`);
      return 2;
    }
    found.push(hit);
  }
  const f = found[0];
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
  const brief = flagBool(args, "brief");
  const shown = dossierContext(loadContextDoc(run), {
    brief,
    compact: flagBool(args, "compact"),
    noContext: flagBool(args, "no-context"),
  });
  // `--brief` is the batch packet: narrow windows, no enclosing bodies, no
  // reachability block. One subagent reading eight findings pays for the full
  // depth eight times; one auditor deciding a single flow wants all of it.
  println(
    found.length > 1 ? renderFamilyDossier(repo, d.graph, found, { context: shown, brief }) : renderFindingDossier(repo, d.graph, f, { context: shown, brief }),
  );
  return 0;
}

/**
 * The CONTEXT.md a dossier prints. `--brief` implies `--compact`: the batch
 * packet exists so a subagent reading eight ids does not pay for eight copies of
 * the same document, and it was still carrying the whole trust model (85 of 132
 * lines on one real run). An unrecognised layout stays whole — losing the threat
 * model silently is worse than repeating it.
 */
export function dossierContext(doc: string | undefined, opts: { brief?: boolean; compact?: boolean; noContext?: boolean }): string | undefined {
  if (opts.noContext || !doc) return undefined;
  return opts.brief || opts.compact ? (compactContextDoc(doc) ?? doc) : doc;
}
