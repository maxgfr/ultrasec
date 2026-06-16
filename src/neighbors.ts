import type { Edge, Graph } from "./graph.js";
import { byStr } from "./util.js";

export interface NeighborLink {
  node: string;
  direction: "out" | "in";
  kind: string;
  weight: number;
  depth: number;
  symbol?: string;
}

export interface NeighborResult {
  target: string;
  links: NeighborLink[];
}

/** BFS over the graph from `target`, out to `depth` hops, both directions. */
export function neighbors(graph: Graph, target: string, depth = 1): NeighborResult {
  const out = new Map<string, Edge[]>();
  const inn = new Map<string, Edge[]>();
  for (const e of graph.edges) {
    (out.get(e.from) ?? out.set(e.from, []).get(e.from)!).push(e);
    (inn.get(e.to) ?? inn.set(e.to, []).get(e.to)!).push(e);
  }

  const seen = new Set<string>([target]);
  const links: NeighborLink[] = [];
  let frontier = [target];

  for (let d = 1; d <= depth; d++) {
    const next: string[] = [];
    for (const node of frontier) {
      for (const e of (out.get(node) ?? []).slice().sort((a, b) => byStr(a.to, b.to))) {
        if (seen.has(e.to)) continue;
        links.push({ node: e.to, direction: "out", kind: e.kind, weight: e.weight, depth: d, symbol: e.toSymbol });
        seen.add(e.to);
        next.push(e.to);
      }
      for (const e of (inn.get(node) ?? []).slice().sort((a, b) => byStr(a.from, b.from))) {
        if (seen.has(e.from)) continue;
        links.push({ node: e.from, direction: "in", kind: e.kind, weight: e.weight, depth: d, symbol: e.toSymbol });
        seen.add(e.from);
        next.push(e.from);
      }
    }
    frontier = next;
  }

  return { target, links };
}
