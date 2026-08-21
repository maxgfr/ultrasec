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

/**
 * What the engine saw about whether the tainted value ACTUALLY ARRIVES — stated,
 * not acted on.
 *
 * Enumeration closes a path on "a source at or above the sink line in the same
 * file". That is co-location, and it is why a literal `script.src = "https://…"`
 * could be reported as DOM XSS. The engine already computed the answer — the
 * def-use walk knows which bindings it was following and whether any of them
 * reach the sink line — and then buried it in a prose footnote that neither the
 * dossier nor the worklist showed.
 *
 * It is surfaced here rather than turned into a rule because tightening
 * enumeration mechanically would trade recall on DOM XSS, which is exactly where
 * this repo's real bugs were. Reading two lines of evidence is cheap; a missed
 * stored XSS is not.
 */
function reachabilityEvidence(f: Finding): string[] {
  const scope = f.sourceScope;
  const flow = f.flow;
  if (!scope && !f.dataflow && !flow) return [];

  const L: string[] = [`## Reachability evidence`, `_What the engine saw. It did not decide — that is this dossier's question._`, ""];

  if (scope)
    L.push(
      `- **source scope**: \`${scope}\`${
        scope === "symbol"
          ? " — the source is in the SAME function as the line that closed the path. Strongest tier."
          : scope === "module"
            ? " — same module scope, different function. Verify the value is actually passed."
            : " — a DIFFERENT function of the same file. This is CO-LOCATION only: the engine has not shown the value travels."
      }`,
    );

  if (f.dataflow)
    L.push(
      `- **def-use**: \`${f.dataflow}\`${
        f.dataflow === "linked" ? " — a binding from the source is mentioned at the sink line." : " — NO binding from the source is mentioned at the sink line."
      }`,
    );
  else if (flow?.tainted?.length)
    L.push(`- **def-use**: undecidable — the walk could not follow the value (used inline, or rebound through state it cannot see).`);

  if (flow?.tainted?.length) L.push(`- **bindings tracked from the source**: ${flow.tainted.map((n) => `\`${n}\``).join(", ")}`);

  if (flow?.assigned) {
    const uses = (flow.tainted ?? []).filter((n) => new RegExp(`\\b${n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`).test(flow.assigned!));
    L.push(`- **value assigned at the sink**: \`${flow.assigned.length > 160 ? `${flow.assigned.slice(0, 160)}…` : flow.assigned}\``);
    // The def-use walk is PER FILE. On a cross-file path the sink's value is a
    // parameter, so "no tracked binding" is the expected reading of a genuine
    // flow — the domxss bench fixture is exactly that shape. Saying "nothing
    // tainted arrives" there would push the reader away from a true positive,
    // which is worse than showing no evidence at all.
    const crossFile = new Set((f.path ?? []).map((p) => p.file)).size > 1;
    L.push(
      uses.length
        ? `  - a tracked binding (${uses.map((n) => `\`${n}\``).join(", ")}) appears in it — there IS an edge into the attribute.`
        : crossFile
          ? `  - no tracked binding appears in it, which is EXPECTED here: the path crosses files, so the assigned value is a parameter and the def-use walk (per-file) cannot follow it. Read the path above to decide whether the caller's value reaches this attribute.`
          : `  - **no tracked binding appears in it**, and the whole path is in ONE file — so the walk could have followed it and did not. Either the value arrives through state this walk cannot see, or nothing tainted arrives here at all. Decide which before rating it.`,
    );
  }

  L.push("");
  return L;
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
  L.push(...reachabilityEvidence(f));
  L.push(`## What to decide`);
  L.push(f.message);
  L.push("");

  // Prior analysis (presence-gated): upstream-agent reasoning ingested as a SIGNAL.
  // Clearly labelled as NOT a verdict — the adjudicator still decides from the code.
  if (f.priorAnalysis) {
    const pa = f.priorAnalysis;
    L.push(`## Prior analysis (signal, not a verdict)`);
    L.push(`_From \`${pa.tool}\` — background only; ultrasec's verify gate, not this, decides the status._`);
    if (pa.revalidationVerdict) L.push(`- ${pa.tool} revalidation verdict: **${pa.revalidationVerdict}** (a hint — confirm it yourself)`);
    if (pa.mitigationsChecked && pa.mitigationsChecked.length) L.push(`- mitigations ${pa.tool} checked: ${pa.mitigationsChecked.join(", ")}`);
    if (pa.reasoning) {
      L.push("");
      L.push(pa.reasoning);
    }
    L.push("");
  }

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
