import { join } from "node:path";
import { readText } from "./walk.js";
import type { RepoScan } from "./scan.js";
import { enclosingSymbolName } from "./scan.js";
import { langForFile, type Sym } from "./lang.js";
import { findSources } from "./catalog.js";
import { AUTH_MARKER } from "./context.js";
import { shortHash, byStr } from "./util.js";
import type { Discovery } from "./investigate.js";
import { parseIdVerdictRows, type ParseResult } from "./apply-parse.js";

// The entry-point × guard matrix — enumerating the vulnerability that is an
// ABSENCE.
//
// Everything else in this engine finds a vulnerability that is a PATTERN: a
// dangerous callee, a tainted flow, a vulnerable version, a key in a file. You
// cannot taint-trace a missing authorization check, because there is no line to
// point at — the bug is that nobody wrote one.
//
// On a real audit that blind spot cost the three worst findings in the repo.
// Four HTTP routes accepted `session_variables` from the request body and then
// called Hasura with the admin secret; anyone on the internet could publish to a
// public government site. The engine saw the file. It reported an unrelated
// candidate on a neighbouring line. It never asked the question the routes
// failed: *is anything checking who is calling this?*
//
// The two halves of that question were already being computed, separately, and
// never crossed:
//
//   • `findSources` finds every request entry point (this is what `map` and
//     `context` count as "attack surface").
//   • `AUTH_MARKER` finds every line that looks like an authentication or
//     authorization check (this is `context`'s "candidate protections" list).
//
// Crossing them is this module. For each handler that reads request data, it
// reports which auth markers appear in that handler's scope — and the ones with
// none become a worklist.
//
// ── What a row is and is not ───────────────────────────────────────────────
//
// A marker in scope is a CANDIDATE guard, not proof. `verifyToken` on line 3
// might be checking something unrelated, might be commented out, might run after
// the object is already read. Conversely a route can be protected by a framework
// middleware, a proxy rule, or a decorator this pass cannot see, and will be
// reported `unguarded` when it is fine.
//
// So the matrix NEVER produces a finding by itself. It produces the question,
// with the code to answer it from, and an auditor's verdict is what turns an
// `unguarded` row into a finding — through the same citation gate every other
// discovery passes. Getting a false `unguarded` is cheap: one read. Never
// asking is what cost the audit.

/** Entry-point kinds an unauthenticated attacker can actually reach.
 *
 *  A CLI argument, an environment variable or stdin is also untrusted input, and
 *  the taint pass treats all of them as sources — but "which authorization check
 *  guards this" is not a question about them. Whoever runs the binary already
 *  has whatever the binary has. Asking it anyway would fill the worklist with
 *  rows that have no answer. */
const REQUEST_KINDS = new Set(["http", "ws"]);

/** Grouping key for request reads that sit outside any function. Parentheses
 *  cannot appear in an identifier, so it can never collide with a real handler. */
const MODULE_SCOPE = "(module scope)";

export const GUARD_VERDICTS = ["guarded", "unguarded", "intentionally-public"] as const;
export type GuardVerdict = (typeof GUARD_VERDICTS)[number];

/** One adjudicated row, as `guards --apply` accepts it back. */
export interface GuardInput {
  id: string;
  verdict: GuardVerdict;
  note?: string;
}

/** Parse a GUARDS.json body. Lives here beside the vocabulary it validates, so
 *  the CLI and the powered pipeline cannot drift apart about what a verdict is. */
export function parseGuardVerdicts(raw: string): ParseResult<GuardInput> {
  return parseIdVerdictRows<GuardVerdict, GuardInput>(raw, {
    wrapperKeys: ["guards", "verdicts"],
    label: "guard verdicts",
    verdicts: GUARD_VERDICTS,
    build: (row, verdict) => ({
      id: row.id as string,
      verdict,
      ...(typeof row.note === "string" && row.note ? { note: row.note } : {}),
    }),
  });
}

/** One auth/authorization marker sighted in a handler's scope. */
export interface GuardSighting {
  line: number;
  hint: string;
}

export interface GuardRow {
  /** Stable, content-derived — so a verdict names one row across re-emissions. */
  id: string;
  file: string;
  /** First request-data read in this handler: where to start reading. */
  line: number;
  /** The enclosing function, when the extractor resolved one. */
  handler?: string;
  /** Entry-point kinds this handler reads (http, ws). */
  kinds: string[];
  /** How many request-data reads this handler makes — a size hint, not a risk. */
  reads: number;
  /** Auth markers found inside `scope`. */
  guards: GuardSighting[];
  /**
   * Where `guards` was searched, weakest evidence last:
   *
   * - `symbol` — the handler's own extent, from the extractor's end line.
   * - `approx` — from the handler's first line to the line before the next
   *   symbol starts. The extractor often omits `endLine` even on the AST tier
   *   (measured: all 49 handlers of one real Next.js monorepo), and the whole
   *   file is a much worse answer than the gap to the next function.
   * - `file` — the file has no other symbol to bound against. For a one-handler
   *   route file this is exact; for a multi-handler file a marker listed here
   *   may guard a different handler.
   */
  scope: "symbol" | "approx" | "file";
  state: "guarded" | "unguarded";
  verdict: null;
}

/**
 * The line range to search for a guard, and how much to trust it.
 *
 * Mirrors `enclosingSymbolName`'s innermost-wins selection, then answers the
 * question that helper does not: where does the symbol END?
 *
 * The extractor frequently leaves `endLine` unset — on one real Next.js
 * monorepo, for every one of 49 handlers, with `extraction.ast: true`. Treating
 * that as "search the whole file" made every row's evidence the file's, which
 * on a multi-handler file can credit one route with another's guard. Bounding
 * by the next symbol's first line instead is the ordinary approximation of a
 * function's extent, and it is right far more often than the file is.
 */
function guardScope(symbols: Sym[], line: number, lineCount: number): { from: number; to: number; scope: GuardRow["scope"] } {
  let best: Sym | undefined;
  for (const s of symbols) {
    if (s.line > line) continue;
    if (s.endLine !== undefined && line > s.endLine) continue;
    if (!best || s.line > best.line || (s.line === best.line && (s.endLine ?? Infinity) <= (best.endLine ?? Infinity))) best = s;
  }
  if (!best) return { from: 1, to: lineCount, scope: "file" };
  if (best.endLine !== undefined) return { from: best.line, to: best.endLine, scope: "symbol" };

  let next = Infinity;
  for (const s of symbols) if (s.line > best.line && s.line < next) next = s.line;
  return next === Infinity ? { from: best.line, to: lineCount, scope: "file" } : { from: best.line, to: next - 1, scope: "approx" };
}

/**
 * Build the entry-point × guard matrix.
 *
 * One row per HANDLER, not per request read: a route that reads `req.query`,
 * `req.body` and `req.headers` is one authorization question, and three rows
 * would be three ways to answer it inconsistently.
 */
export function buildGuardMatrix(scan: RepoScan): GuardRow[] {
  const rows: GuardRow[] = [];

  for (const file of scan.files) {
    const lang = langForFile(file.rel);
    if (!lang) continue;
    const text = readText(join(scan.repo, file.rel));
    const sources = findSources(lang, text, file.rel).filter((s) => REQUEST_KINDS.has(s.kind));
    if (!sources.length) continue;

    const lines = text.split(/\r?\n/);
    // Every auth marker in the file, once — the per-handler scopes index into it.
    const markers: GuardSighting[] = [];
    for (let i = 0; i < lines.length; i++) {
      const m = AUTH_MARKER.exec(lines[i]!);
      if (m) markers.push({ line: i + 1, hint: m[0] });
    }

    // Group the request reads by their enclosing handler. A source outside any
    // symbol (module-level `req` handling, a bare script) groups under the file.
    const byHandler = new Map<string, { line: number; kinds: Set<string>; reads: number; handler?: string }>();
    for (const s of sources) {
      const handler = enclosingSymbolName(file.symbols, s.line);
      const key = handler ?? MODULE_SCOPE;
      const at = byHandler.get(key);
      if (at) {
        at.reads++;
        at.kinds.add(s.kind);
        at.line = Math.min(at.line, s.line);
      } else {
        byHandler.set(key, { line: s.line, kinds: new Set([s.kind]), reads: 1, handler });
      }
    }

    for (const [, h] of byHandler) {
      const { from, to, scope } = guardScope(file.symbols, h.line, lines.length);
      const guards = markers.filter((m) => m.line >= from && m.line <= to);
      rows.push({
        id: shortHash(`guard:${file.rel}:${h.handler ?? ""}`),
        file: file.rel,
        line: h.line,
        ...(h.handler ? { handler: h.handler } : {}),
        kinds: [...h.kinds].sort(byStr),
        reads: h.reads,
        guards,
        scope,
        state: guards.length ? "guarded" : "unguarded",
        verdict: null,
      });
    }
  }

  return rows.sort((a, b) => byStr(a.file, b.file) || a.line - b.line);
}

/** The matrix's headline numbers, for the command line and the report. */
export function guardTotals(rows: readonly GuardRow[]): { handlers: number; unguarded: number; fileScoped: number } {
  return {
    handlers: rows.length,
    unguarded: rows.filter((r) => r.state === "unguarded").length,
    fileScoped: rows.filter((r) => r.scope === "file").length,
  };
}

export function renderGuardsMd(rows: GuardRow[], context?: string): string {
  const t = guardTotals(rows);
  const L: string[] = [`# ultrasec guard matrix (${t.handlers} handler(s), ${t.unguarded} with no visible guard)`, ""];
  L.push(`Every handler that reads request data, and the authentication/authorization markers`);
  L.push(`visible in its scope. This is the question the taint pass cannot ask: a missing`);
  L.push(`authorization check has no line to point at.`);
  L.push("");
  L.push(`For each row set a \`verdict\`:`);
  L.push(`\`guarded\` (a real check protects it) · \`unguarded\` (nothing does — a finding) ·`);
  L.push(`\`intentionally-public\` (health check, login, webhook with its own signature check).`);
  L.push(`Save as GUARDS.json (array of {id, verdict, note?}) and run \`ultrasec guards --apply GUARDS.json\`.`);
  L.push("");
  L.push(`> **A marker is a candidate, not a proof.** \`requireAuth\` in scope may guard a`);
  L.push(`> different branch, run after the object is read, or check authentication where the`);
  L.push(`> route needs authorization. Read the handler. Equally, a route can be protected by`);
  L.push(`> framework middleware, an ingress rule or a decorator this pass cannot see — a`);
  L.push(`> \`unguarded\` row is a question, not an accusation.`);
  L.push("");
  if (t.fileScoped) {
    L.push(`> ⚠️  ${t.fileScoped} row(s) have \`scope: file\`: nothing bounded the handler, so the`);
    L.push(`> markers listed are the whole FILE's and may guard a different handler. (A single-`);
    L.push(`> handler route file is the common case, where file scope is exact.)`);
    L.push("");
  }
  if (context) {
    L.push(`## Project context`);
    L.push(`_From \`CONTEXT.md\`._`);
    L.push("");
    L.push(context);
    L.push("");
  }

  const unguarded = rows.filter((r) => r.state === "unguarded");
  const guarded = rows.filter((r) => r.state === "guarded");

  if (unguarded.length) {
    L.push(`## No visible guard (${unguarded.length}) — read these first`);
    L.push("");
    for (const r of unguarded) {
      L.push(
        `- \`${r.id}\` — \`${r.file}:${r.line}\`${r.handler ? ` in \`${r.handler}()\`` : " (module scope)"} · ${r.kinds.join("/")} · ${r.reads} request read(s)`,
      );
    }
    L.push("");
  }
  if (guarded.length) {
    L.push(`## A guard is visible (${guarded.length}) — confirm it actually applies`);
    L.push("");
    for (const r of guarded) {
      const hints = r.guards
        .slice(0, 3)
        .map((g) => `\`${g.hint}\`:${g.line}`)
        .join(", ");
      L.push(
        `- \`${r.id}\` — \`${r.file}:${r.line}\`${r.handler ? ` in \`${r.handler}()\`` : ""} · ${hints}${r.guards.length > 3 ? ` +${r.guards.length - 3} more` : ""}${r.scope === "symbol" ? "" : ` · ⚠️ ${r.scope}-scoped`}`,
      );
    }
    L.push("");
  }
  if (!rows.length) {
    L.push(`_No handler reads request data in the scanned files. If the app has HTTP routes,`);
    L.push(`the extraction tier or the scope pruned them — check \`manifest.extraction\`._`);
    L.push("");
  }
  return L.join("\n") + "\n";
}

/**
 * Turn an `unguarded` verdict into a grounded Discovery.
 *
 * The citation is the row's own `file:line` — a line the engine read to build
 * the row — so it resolves by construction and passes the grounding gate for the
 * same reason every `investigate` discovery does. The auditor's `note` becomes
 * the evidence; without one the message says only what the matrix established,
 * which is that nothing guards the handler.
 *
 * Severity is deliberately `high`, not `critical`: an unguarded handler is a
 * defeated security boundary, and whether it is catastrophic depends on what the
 * handler DOES — which the matrix does not know and the auditor does. Raising it
 * is a verdict, and verdicts belong to `verify`.
 */
export function guardDiscovery(row: GuardRow, note?: string): Discovery {
  const where = row.handler ? `${row.handler}()` : "module scope";
  return {
    title: `Unauthenticated request handler: ${where} in ${row.file}`,
    category: "authz",
    severity: "high",
    cwe: "CWE-306",
    message:
      `\`${row.file}:${row.line}\`${row.handler ? ` (\`${row.handler}()\`)` : ""} reads request data (${row.kinds.join("/")}, ` +
      `${row.reads} read(s)) and no authentication or authorization marker is visible in ${row.scope === "symbol" ? "the handler's scope" : "the file"}. ` +
      `Adjudicated \`unguarded\` against the guard matrix.` +
      (note ? ` ${note}` : ""),
    file: row.file,
    line: row.line,
  };
}
