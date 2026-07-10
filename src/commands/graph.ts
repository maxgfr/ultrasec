import { resolve } from "node:path";
import { flagStr, flagBool, println, eprintln, type ParsedArgs } from "../util.js";
import { scanRepo } from "../scan.js";
import { buildGraph, type Graph } from "../graph.js";
import { loadDossier } from "../store.js";
import { neighbors } from "../neighbors.js";

// `ultrasec graph <file|symbol> [--run <run> | --repo .] [--depth 1] [--json]`
// Show the cross-file links into/out of a file (or the file defining a symbol).
export function runGraph(args: ParsedArgs): number {
  const target = args._[1];
  const depth = Number(flagStr(args, "depth") ?? "1") || 1;
  if (!target) {
    eprintln("ultrasec graph: need a <file|symbol> argument. e.g. `graph src/db.js`");
    return 2;
  }

  // Run-scoped like every sibling (dossier/paths/triage/verify): when `--run` is
  // given, resolve the graph from that run's graph.json instead of silently
  // re-scanning the CWD — otherwise a node the run plainly lists reports the
  // misleading "not a file node nor a known exported symbol". Without `--run`,
  // fall back to a live `--repo` scan (default CWD), preserving prior behaviour.
  const runFlag = flagStr(args, "run");
  let graph: Graph;
  if (runFlag) {
    try {
      graph = loadDossier(resolve(runFlag)).graph;
    } catch (e) {
      eprintln(`ultrasec graph: ${(e as Error).message}`);
      return 2;
    }
  } else {
    graph = buildGraph(scanRepo(flagStr(args, "repo") ?? "."));
  }

  // Resolve a symbol name to its defining file if the target isn't a file node.
  let node = target;
  if (!graph.files.includes(target)) {
    // Array.isArray guard: a symbol name can collide with an Object.prototype member
    // ("constructor"/"toString"/…), so this plain-object lookup may return an
    // inherited function — treat anything non-array as "not a known symbol".
    const defs = graph.symbolDefs[target];
    if (Array.isArray(defs) && defs.length === 1) node = defs[0]!;
    else if (Array.isArray(defs) && defs.length > 1) {
      eprintln(`ultrasec graph: symbol "${target}" is defined in ${defs.length} files: ${defs.join(", ")}`);
      return 2;
    } else {
      eprintln(`ultrasec graph: "${target}" is not a file node nor a known exported symbol.`);
      return 2;
    }
  }

  const result = neighbors(graph, node, depth);

  if (flagBool(args, "json")) {
    println(JSON.stringify(result, null, 2));
    return 0;
  }

  println(`${node}  (depth ${depth})`);
  if (!result.links.length) {
    println("  (no links)");
    return 0;
  }
  for (const l of result.links) {
    const arrow = l.direction === "out" ? "→" : "←";
    const sym = l.symbol ? ` [${l.symbol}]` : "";
    println(`  ${arrow} ${l.kind.padEnd(6)} ${l.node}${sym}  (d${l.depth})`);
  }
  return 0;
}
