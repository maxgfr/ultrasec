import type { Dossier } from "./store.js";
import type { Finding } from "./types.js";
import { byStr } from "./util.js";
import { coerceRows, parseDiscoveryRow, type DroppedRow, type NormalizedRow, type ParseResult } from "./apply-parse.js";
import type { Discovery } from "./investigate.js";

// The variant-analysis stage. Every stage before it asks "is THIS candidate
// real?"; this one asks the question that actually closes an audit: **where else
// does the same root cause appear?**
//
// One bad habit produces many instances — a helper everyone calls without the
// guard, a validator applied on three routes out of five, a pattern
// copy-pasted between services. Confirming one and stopping leaves the others
// in production, and they are the cheapest bugs in the whole audit to find,
// because you already know exactly what you are looking for.
//
// The engine's contribution is deliberately small: it groups confirmed findings
// by root-cause SHAPE and lists the mechanical neighbours (same sink callee,
// same sink file, same CWE). Deciding what the root cause actually *is* — the
// why, not the what — is the judgment the stage exists to prompt.

/** How a candidate variant was reached from the seed. Recorded so a reviewer can
 *  see why each one is on the list, and discount the weak axes. */
export const VARIANT_AXES = ["same-sink-callee", "same-file", "same-cwe", "same-caller", "same-interface", "manual"] as const;
export type VariantAxis = (typeof VARIANT_AXES)[number];

/** One mechanical neighbour of a seed — a place to LOOK, never a finding. */
export interface Neighbour {
  file: string;
  line: number;
  axis: VariantAxis;
  /** The other finding's id when the neighbour came from the dossier. */
  id?: string;
  what: string;
}

export interface VariantItem {
  /** The confirmed finding this hunt starts from. */
  seedId: string;
  severity: string;
  cwe?: string;
  title: string;
  /** Where the seed's dangerous operation is. */
  at: string;
  /** The callee/operation to build the exact match around. */
  operation: string;
  /** Mechanical neighbours the engine can already see. Starting points, not results. */
  neighbours: Neighbour[];
  // ── Filled by the agent ────────────────────────────────────────────────
  /** The WHY, in one sentence. Not "SQL injection in getUser" but "every query
   *  helper in db/ concatenates the id because the wrapper never took params". */
  rootCause: string;
  /** Search patterns tried, in order, with what each returned. Failed patterns
   *  are kept: they are how a reader knows the search space was actually walked. */
  patterns: { pattern: string; matched: number; note: string }[];
  /** Confirmed variants, as citation-gated discoveries. */
  variants: Discovery[];
  /** A Semgrep rule that would catch the whole family in CI. */
  regressionRule: string;
}

/** The sink location of a finding, which is what a variant hunt keys on. */
function sinkOf(f: Finding): { file: string; line: number } | null {
  if (f.sink) return { file: f.sink.file, line: f.sink.line };
  const last = f.path?.[f.path.length - 1];
  return last ? { file: last.file, line: last.line } : null;
}

/** The callee a taint finding reached, recovered from its title. */
function operationOf(f: Finding): string {
  const m = /reaches (.+)$/.exec(f.title);
  return m?.[1] ?? f.sink?.kind ?? f.category;
}

/**
 * Seeds are CONFIRMED findings only. Hunting variants of a candidate you have not
 * proved multiplies a guess; hunting variants of a proved bug multiplies
 * knowledge — and the whole value of the stage is that the root cause is already
 * established before the search starts.
 */
function seeds(findings: Finding[]): Finding[] {
  return findings.filter((f) => f.status === "confirmed");
}

export function buildVariantWorklist(dossier: Dossier): VariantItem[] {
  const all = dossier.findings;
  return seeds(all)
    .slice()
    .sort((a, b) => byStr(a.id, b.id))
    .map((f) => {
      const sink = sinkOf(f);
      const op = operationOf(f);
      const neighbours: Neighbour[] = [];
      const seen = new Set<string>();
      const add = (n: Neighbour) => {
        const key = `${n.file}:${n.line}:${n.axis}`;
        if (seen.has(key) || (sink && n.file === sink.file && n.line === sink.line)) return;
        seen.add(key);
        neighbours.push(n);
      };

      for (const o of all) {
        if (o.id === f.id) continue;
        const os = sinkOf(o);
        if (!os) continue;
        // Same dangerous operation elsewhere: the strongest mechanical signal —
        // one unguarded helper usually has more than one unguarded caller.
        if (operationOf(o) === op) add({ file: os.file, line: os.line, axis: "same-sink-callee", id: o.id, what: o.title });
        else if (sink && os.file === sink.file) add({ file: os.file, line: os.line, axis: "same-file", id: o.id, what: o.title });
        else if (o.cwe && o.cwe === f.cwe) add({ file: os.file, line: os.line, axis: "same-cwe", id: o.id, what: o.title });
      }

      return {
        seedId: f.id,
        severity: f.severity,
        cwe: f.cwe,
        title: f.title,
        at: sink ? `${sink.file}:${sink.line}` : "—",
        operation: op,
        neighbours: neighbours.sort((a, b) => byStr(a.axis, b.axis) || byStr(a.file, b.file) || a.line - b.line).slice(0, 25),
        rootCause: "",
        patterns: [],
        variants: [],
        regressionRule: "",
      };
    });
}

export function renderVariantsMd(items: VariantItem[], context?: string): string {
  const L: string[] = [];
  L.push(`# ultrasec variant analysis (${items.length} confirmed seed${items.length === 1 ? "" : "s"})`);
  L.push("");
  if (!items.length) {
    L.push(`No confirmed findings yet — variants are hunted from proved bugs, not candidates.`);
    L.push(`Run \`verify --apply\` first, then re-emit.`);
    return L.join("\n") + "\n";
  }
  L.push(`One root cause almost always produced more than one instance. For each seed below:`);
  L.push("");
  L.push(`1. **State the root cause** — the *why*, not the *what*. "every helper in \`db/\``);
  L.push(`   concatenates because the wrapper never accepted parameters", not "SQL injection".`);
  L.push(`2. **Build an EXACT match first** and check it finds the known instance. A pattern that`);
  L.push(`   returns zero results means the bug is misunderstood — everything after it is invalid.`);
  L.push(`3. **Generalize one dimension at a time**, re-reading every result. Abstracting two at`);
  L.push(`   once makes the new noise unattributable.`);
  L.push(`4. **Stop when over half the matches are false.**`);
  L.push(`5. **Record the patterns that failed too** — that is how a reader knows the space was walked.`);
  L.push("");
  L.push(`Emit variants as \`Discovery[]\` (same shape as \`investigate\`), so every one is`);
  L.push(`citation-gated before it is folded in. Then write \`regressionRule\`: a Semgrep rule that`);
  L.push(`catches the whole family, so the fix cannot quietly regress.`);
  L.push("");
  L.push(`> Neighbours below are places to LOOK, produced mechanically. Proximity is not a finding.`);
  L.push("");
  if (context) {
    L.push(`## Project context`);
    L.push(`_From \`CONTEXT.md\` — background, never a verdict._`);
    L.push("");
    L.push(context);
    L.push("");
  }
  for (const it of items) {
    L.push(`## ${it.seedId} — [${it.severity}] ${it.title}`);
    L.push(`- confirmed at \`${it.at}\`${it.cwe ? ` · ${it.cwe}` : ""}`);
    L.push(`- operation: \`${it.operation}\``);
    if (it.neighbours.length) {
      L.push(`- mechanical neighbours (${it.neighbours.length}):`);
      for (const n of it.neighbours) L.push(`  - \`${n.file}:${n.line}\` · _${n.axis}_ · ${n.what}`);
    } else {
      L.push(`- no mechanical neighbour in the dossier — search the repo directly (\`rg\`), the`);
      L.push(`  family may be entirely un-enumerated.`);
    }
    L.push("");
  }
  return L.join("\n") + "\n";
}

/** What `--apply` accepts back: the filled worklist, or just its judgment half. */
export interface VariantResult {
  seedId: string;
  rootCause?: string;
  patterns?: { pattern: string; matched: number; note: string }[];
  variants: Discovery[];
  regressionRule?: string;
}

export function parseVariantResults(raw: string): ParseResult<VariantResult> {
  const arr = coerceRows(JSON.parse(raw) as unknown, ["variants", "results"], "variant results");
  const rows: VariantResult[] = [];
  const dropped: DroppedRow[] = [];
  const normalized: NormalizedRow[] = [];

  for (const [index, entry] of (arr as unknown[]).entries()) {
    const v = entry as Record<string, unknown>;
    if (!v || typeof v !== "object") {
      dropped.push({ index, reason: "not an object" });
      continue;
    }
    if (typeof v.seedId !== "string" || !v.seedId) {
      dropped.push({ index, reason: "missing seedId (which confirmed finding is this a hunt for?)" });
      continue;
    }
    // Validate each variant with the SAME row parser `investigate --apply` uses.
    // This line used to read `v.variants as Discovery[]` — a type assertion,
    // erased at runtime — so a malformed variant reached `ingestDiscoveries`
    // unchecked. The variants a hunt returns are discoveries; they earn the same
    // gate, and a refused one is reported with its seed and its position rather
    // than crashing the fold.
    const variants: Discovery[] = [];
    for (const [at, candidate] of (Array.isArray(v.variants) ? (v.variants as unknown[]) : []).entries()) {
      const parsed = parseDiscoveryRow(candidate);
      if (!parsed.row) {
        dropped.push({ index, reason: `variants[${at}] (seed ${v.seedId}): ${parsed.reason}` });
        continue;
      }
      if (parsed.note) normalized.push({ index, note: `variants[${at}] (seed ${v.seedId}): ${parsed.note}` });
      variants.push(parsed.row);
    }
    rows.push({
      seedId: v.seedId,
      rootCause: typeof v.rootCause === "string" ? v.rootCause : undefined,
      patterns: Array.isArray(v.patterns) ? (v.patterns as VariantResult["patterns"]) : undefined,
      variants,
      regressionRule: typeof v.regressionRule === "string" ? v.regressionRule : undefined,
    });
  }
  if (rows.length === 0 && (arr as unknown[]).length > 0) {
    const detail = dropped.map((d) => `row ${d.index}: ${d.reason}`).join("; ");
    throw new Error(
      `variant results: all ${(arr as unknown[]).length} row(s) were unusable — nothing folded (fail-closed)${detail ? ` — ${detail}` : ""}`,
    );
  }
  // Presence-gated, like `parseDiscoveries`: no fold ⇒ shape-identical to before.
  return { rows, dropped, ...(normalized.length ? { normalized } : {}) };
}

/**
 * Render the regression rules the hunt produced as one Semgrep file.
 *
 * This is the point at which an audit stops being a document. A finding is fixed
 * once; a rule keeps it fixed. Emitting the rules the auditor already wrote costs
 * nothing and hands the project the guard along with the bug.
 */
export function renderRegressionRules(results: VariantResult[]): string {
  const withRules = results.filter((r) => r.regressionRule?.trim());
  if (!withRules.length) return "";
  const L: string[] = [
    "# ultrasec — regression rules from variant analysis.",
    "# One rule per confirmed root cause, authored by the auditor while the bug was",
    "# in front of them. Run in CI: `semgrep --config ultrasec-variants.yaml`.",
    "rules:",
  ];
  for (const r of withRules) {
    L.push(`  # seed ${r.seedId}${r.rootCause ? ` — ${r.rootCause.replace(/\n/g, " ")}` : ""}`);
    for (const line of r.regressionRule!.trimEnd().split("\n")) L.push(`  ${line}`);
    L.push("");
  }
  return L.join("\n");
}
