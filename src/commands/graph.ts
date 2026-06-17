import { flagStr, flagBool, println, eprintln, type ParsedArgs } from "../util.js";
import { scanRepo } from "../scan.js";
import { buildGraph } from "../graph.js";
import { neighbors } from "../neighbors.js";

// `ultrasec graph <file|symbol> [--repo .] [--depth 1] [--json]`
// Show the cross-file links into/out of a file (or the file defining a symbol).
export function runGraph(args: ParsedArgs): number {
  const repo = flagStr(args, "repo") ?? ".";
  const target = args._[1];
  const depth = Number(flagStr(args, "depth") ?? "1") || 1;
  if (!target) {
    eprintln("ultrasec graph: need a <file|symbol> argument. e.g. `graph src/db.js`");
    return 2;
  }

  const graph = buildGraph(scanRepo(repo));

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
