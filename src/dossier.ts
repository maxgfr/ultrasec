import { join } from "node:path";
import { readText } from "./walk.js";
import { neighbors } from "./neighbors.js";
import type { Graph } from "./graph.js";
import type { Finding, PathStep } from "./types.js";

// The grounding packet for ONE finding: the real source code along the cross-file
// path (so the AI reasons from evidence, not memory), plus graph neighbours of
// the sink file. This is what a verification subagent reads to adjudicate.

function excerpt(repo: string, step: PathStep, ctx = 3): string {
  const lines = readText(join(repo, step.file)).split(/\r?\n/);
  const lo = Math.max(1, step.line - ctx);
  const hi = Math.min(lines.length, step.line + ctx);
  const out: string[] = [];
  for (let n = lo; n <= hi; n++) {
    const marker = n === step.line ? ">>" : "  ";
    out.push(`${marker} ${String(n).padStart(4)} | ${lines[n - 1] ?? ""}`);
  }
  return out.join("\n");
}

export function renderFindingDossier(repo: string, graph: Graph, f: Finding, context?: string): string {
  const L: string[] = [];
  L.push(`# ${f.id} — ${f.title}`);
  L.push("");
  L.push(`- severity: ${f.severity} · confidence: ${f.confidence} · status: ${f.status}`);
  if (f.cwe) L.push(`- ${f.cwe} — ${(f.references ?? [])[0] ?? ""}`);
  L.push(`- category: ${f.category}${f.tool !== "ultrasec" ? ` · reported by ${f.tool}` : ""}`);
  L.push("");
  // Project context (presence-gated): the agent-authored CONTEXT.md, so the
  // adjudicator reasons WITH the project's trust model. Evidence only — it never
  // changes the verdict. Absent CONTEXT.md ⇒ this block is omitted (byte-identical).
  if (context) {
    L.push(`## Project context`);
    L.push(`_From \`CONTEXT.md\` — background to judge reachability/exploitability; not a verdict._`);
    L.push("");
    L.push(context);
    L.push("");
  }
  L.push(`## What to decide`);
  L.push(f.message);
  L.push("");

  if (f.path && f.path.length) {
    L.push(`## Cross-file path (source → sink)`);
    L.push("");
    f.path.forEach((step, i) => {
      const tag = i === 0 ? "SOURCE" : i === f.path!.length - 1 ? "SINK" : "HOP";
      L.push(`### ${i + 1}. [${tag}] ${step.file}:${step.line}${step.symbol ? ` — in ${step.symbol}()` : ""}`);
      L.push(`_${step.why}_`);
      L.push("```");
      L.push(excerpt(repo, step));
      L.push("```");
      L.push("");
    });
  } else if (f.sink) {
    L.push(`## Location`);
    L.push("```");
    L.push(excerpt(repo, { file: f.sink.file, line: f.sink.line, why: "" }));
    L.push("```");
    L.push("");
  }

  // Neighbours of the sink file help judge reachability (who else calls in).
  const anchor = f.sink?.file ?? f.path?.[f.path.length - 1]?.file;
  if (anchor && graph.files.includes(anchor)) {
    const nb = neighbors(graph, anchor, 1).links;
    if (nb.length) {
      L.push(`## Graph neighbours of \`${anchor}\``);
      for (const l of nb) {
        const arrow = l.direction === "out" ? "→" : "←";
        L.push(`- ${arrow} ${l.kind} ${l.node}${l.symbol ? ` [${l.symbol}]` : ""}`);
      }
      L.push("");
    }
  }

  L.push(`## How to verify`);
  L.push(`1. Confirm the SOURCE is genuinely attacker-controlled.`);
  L.push(`2. Follow each HOP — does the tainted value actually pass through unchanged?`);
  L.push(`3. Check for a sanitizer/validator/authz guard anywhere on the path.`);
  L.push(`4. Confirm the SINK is exploitable with the value that arrives.`);
  L.push(`5. Record \`supported\` / \`partial\` / \`unsupported\` / \`refuted\` via \`ultrasec verify\`.`);
  L.push(`   If unsure and severity is high, leave it **needs-human** — do not dismiss.`);
  return L.join("\n") + "\n";
}
