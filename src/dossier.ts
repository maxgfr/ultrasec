import { extname, join } from "node:path";
import { readText } from "./walk.js";
import { neighbors } from "./neighbors.js";
import { AUTH_MARKER, THROTTLE_MARKER } from "./context.js";
import { findRouteEntryPoints, findSanitizers } from "./catalog.js";
import { langForFile } from "./lang.js";
import { extractSymbols } from "./vendor/codeindex-engine.mjs";
import type { Graph } from "./graph.js";
import type { Finding, PathStep } from "./types.js";

// The grounding packet for ONE finding: the real source code along the cross-file
// path (so the AI reasons from evidence, not memory), plus graph neighbours of
// the sink file. This is what a verification subagent reads to adjudicate.
//
// ── How much code is enough ────────────────────────────────────────────────
//
// It used to be three lines either side of each hop. That is enough to see the
// call and nothing else: not the validation eight lines up, not the early
// `return 403`, not the fact that the whole function is behind a feature flag.
// An adjudicator working from it either guesses or opens the file — and if the
// answer is always "open the file", the packet is not doing its job.
//
// So: twelve lines by default, and for the SOURCE and the SINK the WHOLE
// enclosing function when it is small enough to read. Plus the questions a
// three-line window can never answer — who calls this, which route exposes it,
// is there a guard, is there a sanitizer — under "Who can reach this".
//
// `--brief` restores the compact packet for batch fan-out, where a subagent
// gets eight of these at once.

/** Lines of context around a hop. Three showed the call and hid its guard. */
const CTX = 12;

/** An enclosing function printed in full only up to this many lines; past it,
 *  the window. A 400-line React component is not evidence, it is a wall. */
const MAX_ENCLOSING = 80;

function fileLines(repo: string, file: string): string[] {
  return readText(join(repo, file)).split(/\r?\n/);
}

function numbered(lines: readonly string[], from: number, to: number, mark: number): string {
  const out: string[] = [];
  for (let n = from; n <= to; n++) {
    const marker = n === mark ? ">>" : "  ";
    out.push(`${marker} ${String(n).padStart(4)} | ${lines[n - 1] ?? ""}`);
  }
  return out.join("\n");
}

function excerpt(repo: string, step: PathStep, ctx = CTX): string {
  const lines = fileLines(repo, step.file);
  return numbered(lines, Math.max(1, step.line - ctx), Math.min(lines.length, step.line + ctx), step.line);
}

/**
 * The function a line sits in, and where it ends.
 *
 * `extractSymbols` is codeindex's per-file extractor — one file, synchronous,
 * no repo scan and no grammar download, which is what makes this affordable in
 * a command that renders a single finding. At the regex tier it reports `line`
 * but not `endLine`, so the extent is bounded by the next symbol that opens
 * below. That under-reports a nested function and never over-reports one, which
 * is the right direction: showing too little code is a smaller lie than
 * attributing a neighbouring function's guard to this one.
 */
interface Enclosing {
  name: string;
  from: number;
  to: number;
}

/** Symbol kinds that are references, not definitions with a body. */
const NOT_A_BODY = new Set(["import", "export", "reexport", "type", "interface"]);

function enclosingOf(repo: string, file: string, line: number, lines: readonly string[]): Enclosing | undefined {
  let syms: ReturnType<typeof extractSymbols>;
  try {
    syms = extractSymbols(file, extname(file), lines.join("\n"));
  } catch {
    return undefined; // an unsupported extension is not an error here
  }
  const bodies = syms.filter((x) => !NOT_A_BODY.has(x.kind)).sort((a, b) => a.line - b.line);
  let best: (typeof bodies)[number] | undefined;
  for (const x of bodies) {
    if (x.line > line) continue;
    if (x.endLine !== undefined && line > x.endLine) continue;
    if (!best || x.line > best.line) best = x;
  }
  if (!best) return undefined;
  const next = bodies.find((x) => x.line > best!.line);
  const to = best.endLine ?? (next ? next.line - 1 : lines.length);
  return { name: best.name, from: best.line, to: Math.max(best.line, to) };
}

/** The enclosing function in full when it is readable, else the window. */
function stepCode(repo: string, step: PathStep, whole: boolean): string {
  const lines = fileLines(repo, step.file);
  if (!whole) return numbered(lines, Math.max(1, step.line - CTX), Math.min(lines.length, step.line + CTX), step.line);
  const enc = enclosingOf(repo, step.file, step.line, lines);
  if (!enc || enc.to - enc.from + 1 > MAX_ENCLOSING) {
    return numbered(lines, Math.max(1, step.line - CTX), Math.min(lines.length, step.line + CTX), step.line);
  }
  return numbered(lines, enc.from, Math.min(lines.length, enc.to), step.line);
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

/**
 * The questions a code window cannot answer.
 *
 * An adjudicator deciding "is this reachable and exploitable" needs four things
 * the path itself never states: which HTTP route exposes the entry point, who
 * else calls into it, whether anything authenticates the caller, and whether
 * anything neutralises the value on the way. Every one is already computed
 * somewhere in this engine — `catalog.ts` knows route shapes and sanitizers,
 * `graph.callersBySymbol` is the reverse call index the taint walk itself
 * walks, `context.ts` owns the auth vocabulary the guard matrix uses — and none
 * of it reached the packet the agent actually reads.
 *
 * Everything here is EVIDENCE, stated as what was and was not found. "No auth
 * marker in this file" is not "unauthenticated": the guard may be a route-level
 * middleware, a proxy, or a platform. Saying which was checked lets the reader
 * disagree with the check instead of with a verdict.
 */
function reachability(repo: string, graph: Graph, f: Finding): string[] {
  const entry = f.path?.[0] ?? f.source;
  // Only a real `sink` carries a `kind`, and the kind is what selects the
  // sanitizer vocabulary — a path's last step is a location, not a classified
  // operation, so it cannot stand in for one here.
  const sinkKind = f.sink?.kind;
  if (!entry && !f.sink) return [];

  const L: string[] = [`## Who can reach this`, `_Evidence, not a verdict: each line says what was looked for and what was found._`, ""];
  let said = false;

  // ── The route that exposes the entry point ───────────────────────────────
  if (entry) {
    let routes: ReturnType<typeof findRouteEntryPoints> = [];
    try {
      routes = findRouteEntryPoints(entry.file, readText(join(repo, entry.file)));
    } catch {
      /* unreadable file: the excerpts above already fail loudly */
    }
    if (routes.length) {
      // Named as a CANDIDATE, not asserted. The handler patterns are
      // deliberately loose — Next.js Pages Router has no marker beyond "the
      // default export of a file under pages/api", so the matcher accepts any
      // function declaration in such a file and over-matches every helper
      // beside the real handler. Saying "this entry point IS the route" on that
      // evidence would be a claim the catalog never made; saying which lines
      // matched, and whether the entry is one of them, is what it did make.
      const onEntry = routes.some((r) => r.line === entry.line);
      const at = routes
        .slice(0, 6)
        .map((r) => r.line)
        .join(", ");
      L.push(`- **route file**: ${routes[0]!.title} — ${routes.length} handler declaration(s) matched (line ${at}${routes.length > 6 ? ", …" : ""}).`);
      L.push(
        onEntry
          ? `  - the entry point at \`${entry.file}:${entry.line}\` is one of them — reachable over the network if this file is routed.`
          : `  - the entry point at \`${entry.file}:${entry.line}\` is NOT one of them: it is a helper, so follow the callers below to find what exposes it.`,
      );
      said = true;
    } else {
      L.push(
        `- **route file**: no handler declaration matched in \`${entry.file}\` — this entry point is reached from other code, not directly over the network.`,
      );
      said = true;
    }

    // ── Who calls the entry symbol ─────────────────────────────────────────
    const sym = f.path?.[0]?.symbol ?? undefined;
    const callers = sym ? (graph.callersBySymbol?.[sym] ?? []) : [];
    if (sym) {
      const outside = callers.filter((c) => c.file !== entry.file);
      if (callers.length) {
        const shown = callers.slice(0, 8).map((c) => `\`${c.file}:${c.line}\`${c.symbol ? ` in ${c.symbol}()` : ""}`);
        L.push(`- **callers of \`${sym}()\`**: ${shown.join(" · ")}${callers.length > shown.length ? ` (+${callers.length - shown.length} more)` : ""}`);
        if (outside.length) L.push(`  - ${outside.length} from OTHER files — the entry point has more than one way in.`);
      } else {
        L.push(
          `- **callers of \`${sym}()\`**: none in the call index — either it is the outermost entry point, or it is invoked dynamically (a router table, a decorator, reflection).`,
        );
      }
      said = true;
    }

    // ── Is anything authenticating the caller ──────────────────────────────
    try {
      const text = readText(join(repo, entry.file));
      const hit = text.split(/\r?\n/).findIndex((l) => AUTH_MARKER.test(l));
      L.push(
        hit >= 0
          ? `- **auth marker in this file**: \`${entry.file}:${hit + 1}\` — a CANDIDATE guard; confirm it runs before the object is touched, on this path.`
          : `- **auth marker in this file**: NONE. Not proof the route is public — the guard may be middleware, a proxy or the platform — but nothing in this file authenticates the caller.`,
      );
      const thr = text.split(/\r?\n/).findIndex((l) => THROTTLE_MARKER.test(l));
      if (thr < 0) L.push(`- **rate limit in this file**: NONE — relevant if the sink is expensive or the flow is an oracle.`);
      said = true;
    } catch {
      /* already reported above */
    }
  }

  // ── Anything neutralising the value on the way ───────────────────────────
  if (f.path?.length && sinkKind) {
    const hits: string[] = [];
    for (const step of f.path) {
      let lines: string[];
      try {
        lines = fileLines(repo, step.file);
      } catch {
        continue;
      }
      const stepLang = langForFile(step.file);
      if (!stepLang) continue;
      for (let n = Math.max(1, step.line - CTX); n <= Math.min(lines.length, step.line + CTX); n++) {
        for (const note of findSanitizers(stepLang, lines[n - 1] ?? "", sinkKind)) hits.push(`\`${step.file}:${n}\` ${note}`);
      }
    }
    const uniq = [...new Set(hits)];
    L.push(
      uniq.length
        ? `- **sanitizers near the path**: ${uniq.slice(0, 6).join(" · ")}${uniq.length > 6 ? ` (+${uniq.length - 6})` : ""} — check each actually covers THIS value.`
        : `- **sanitizers near the path**: none found within ${CTX} lines of any hop. Absence of a known pattern, not proof the value is raw.`,
    );
    said = true;
  }

  if (!said) return [];
  L.push("");
  return L;
}

export interface DossierOptions {
  /** The agent-authored CONTEXT.md, folded in as evidence. */
  context?: string;
  /**
   * The compact packet: narrow windows, no enclosing bodies, no reachability
   * section. For batch fan-out, where one subagent reads eight of these.
   */
  brief?: boolean;
}

export function renderFindingDossier(repo: string, graph: Graph, f: Finding, options: DossierOptions | string = {}): string {
  // Callers passed the context string positionally before `brief` existed.
  const opts: DossierOptions = typeof options === "string" ? { context: options } : options;
  const context = opts.context;
  const brief = opts.brief === true;
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
      const last = i === f.path!.length - 1;
      const tag = i === 0 ? "SOURCE" : last ? "SINK" : "HOP";
      // The two ends carry the decision — is the input attacker-controlled, is
      // the operation exploitable with what arrives — so they get the whole
      // enclosing function. The hops in between only have to show the value
      // passing through.
      const whole = !brief && (i === 0 || last);
      L.push(`### ${i + 1}. [${tag}] ${step.file}:${step.line}${step.symbol ? ` — in ${step.symbol}()` : ""}`);
      L.push(`_${step.why}_`);
      L.push("```");
      L.push(stepCode(repo, step, whole));
      L.push("```");
      L.push("");
    });
  } else if (f.sink) {
    L.push(`## Location`);
    L.push("```");
    L.push(stepCode(repo, { file: f.sink.file, line: f.sink.line, why: "" }, !brief));
    L.push("```");
    L.push("");
  }

  if (!brief) L.push(...reachability(repo, graph, f));

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
