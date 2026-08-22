import { join } from "node:path";
import { readText } from "./walk.js";
import type { RepoScan } from "./scan.js";
import { enclosingSymbolName } from "./scan.js";
import { langForFile, type Sym } from "./lang.js";
import { findSources } from "./catalog.js";
import { AUTH_MARKER, THROTTLE_MARKER } from "./context.js";
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

// ── Lenses ─────────────────────────────────────────────────────────────────
//
// The matrix asks one question — "which markers of KIND X are visible in this
// handler's scope?" — and the kind is the only thing that varies. Authorization
// was the first; rate limiting is the second, and it is the same shape of
// absence for the same reason: `grep -E 'rate|429'` returning nothing across a
// whole repository is a FACT about the application, established by hand on a
// real audit and written up as one finding, while the engine could only carry
// "missing rate limiting" as advice in a hint string that no run ever answered.
//
// Keeping it as a lens rather than a second command is deliberate: two commands
// would be two copies of the scope arithmetic, the "one architectural fact"
// paragraph and the citation contract, free to drift apart.

export const GUARD_LENSES = ["auth", "throttle"] as const;
export type GuardLens = (typeof GUARD_LENSES)[number];

/** Handlers whose path or name says they are an authentication endpoint. On
 *  those, missing throttling is not a capacity problem — it is credential
 *  stuffing and account enumeration, which is a different finding with a
 *  different CWE. Matched on the file path AND the handler name, because a repo
 *  may carry either convention. */
const LOGIN_SHAPE =
  /\b(sign-?in|log-?in|log-?on|auth|password|passwd|reset|forgot|recover|register|sign-?up|otp|mfa|2fa|token|verify|magic-?link|invite|activation)\b/i;

interface LensSpec {
  /** The vocabulary of markers this lens looks for. */
  marker: RegExp;
  /** Verdicts `--apply` accepts, in the order [present, absent, waived]. */
  verdicts: readonly [string, string, string];
  /** Worklist artefact stem — so both lenses' worklists can coexist in a run. */
  stem: string;
  /** Manifest pass key this lens records, for `coverage`. */
  pass: "guards" | "throttle";
}

export const LENSES: Record<GuardLens, LensSpec> = {
  auth: {
    marker: AUTH_MARKER,
    verdicts: ["guarded", "unguarded", "intentionally-public"],
    stem: "GUARDS",
    pass: "guards",
  },
  throttle: {
    marker: THROTTLE_MARKER,
    verdicts: ["throttled", "unthrottled", "not-abusable"],
    stem: "THROTTLE",
    pass: "throttle",
  },
};

/** The auth lens's vocabulary, kept under its original name — it is what every
 *  existing GUARDS.json and every doc says. */
export const GUARD_VERDICTS = LENSES.auth.verdicts;
export type GuardVerdict = string;

/** One adjudicated row, as `guards --apply` accepts it back. */
export interface GuardInput {
  id: string;
  verdict: GuardVerdict;
  note?: string;
}

/** Parse a GUARDS.json body. Lives here beside the vocabulary it validates, so
 *  the CLI and the powered pipeline cannot drift apart about what a verdict is.
 *  The vocabulary is per-lens: a `guarded` verdict on a throttle worklist is a
 *  category error and is refused with the rest of the malformed rows. */
export function parseGuardVerdicts(raw: string, lens: GuardLens = "auth"): ParseResult<GuardInput> {
  const spec = LENSES[lens];
  return parseIdVerdictRows<GuardVerdict, GuardInput>(raw, {
    wrapperKeys: ["guards", "verdicts"],
    label: `${lens === "auth" ? "guard" : "throttle"} verdicts`,
    verdicts: spec.verdicts,
    build: (row, verdict) => ({
      id: row.id as string,
      verdict,
      ...(typeof row.note === "string" && row.note ? { note: row.note } : {}),
    }),
  });
}

/** One marker of the active lens's kind, sighted in a handler's scope. */
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
  /** Markers of the active lens's kind found inside `scope`. */
  guards: GuardSighting[];
  /** The lens this row was built under. Carried on the row so a verdict, a
   *  discovery and a rendered brief can never disagree about which question was
   *  asked. Absent on rows built before lenses existed ⇒ `auth`. */
  lens?: GuardLens;
  /** The handler's path or name says it is an authentication endpoint. Only the
   *  throttle lens acts on it, and what it changes is the class: on a login
   *  route, no throttling is credential stuffing and account enumeration
   *  (CWE-307/CWE-204), not a capacity problem (CWE-770). */
  loginShape?: boolean;
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
 * Build the entry-point × marker matrix for one lens.
 *
 * One row per HANDLER, not per request read: a route that reads `req.query`,
 * `req.body` and `req.headers` is one authorization question, and three rows
 * would be three ways to answer it inconsistently.
 *
 * `lens` defaults to `auth`, so every existing caller gets exactly the matrix it
 * got before lenses existed.
 */
export function buildGuardMatrix(scan: RepoScan, lens: GuardLens = "auth"): GuardRow[] {
  const spec = LENSES[lens];
  const rows: GuardRow[] = [];

  for (const file of scan.files) {
    const lang = langForFile(file.rel);
    if (!lang) continue;
    const text = readText(join(scan.repo, file.rel));
    const sources = findSources(lang, text, file.rel).filter((s) => REQUEST_KINDS.has(s.kind));
    if (!sources.length) continue;

    const lines = text.split(/\r?\n/);
    // Every marker in the file, once — the per-handler scopes index into it.
    const markers: GuardSighting[] = [];
    for (let i = 0; i < lines.length; i++) {
      const m = spec.marker.exec(lines[i]!);
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
        // The auth lens keeps its historical id, so a GUARDS.json written before
        // lenses existed still names the same rows. A throttle row is a
        // different question about the same handler and needs its own id.
        id: shortHash(lens === "auth" ? `guard:${file.rel}:${h.handler ?? ""}` : `guard:${lens}:${file.rel}:${h.handler ?? ""}`),
        file: file.rel,
        line: h.line,
        ...(h.handler ? { handler: h.handler } : {}),
        kinds: [...h.kinds].sort(byStr),
        reads: h.reads,
        guards,
        ...(lens === "auth" ? {} : { lens }),
        ...(LOGIN_SHAPE.test(file.rel) || (h.handler ? LOGIN_SHAPE.test(h.handler) : false) ? { loginShape: true } : {}),
        scope,
        state: guards.length ? "guarded" : "unguarded",
        verdict: null,
      });
    }
  }

  return rows.sort((a, b) => byStr(a.file, b.file) || a.line - b.line);
}

/**
 * The matrix's headline numbers, for the command line and the report.
 *
 * `noMarkerAnywhere` is the one that changes what a reader should DO. Tested
 * against a public information site with no login at all, the matrix reported
 * 21 handlers, 21 unguarded — each demanding an `intentionally-public` verdict
 * for what is a single architectural fact: this application has no
 * authentication mechanism. Twenty-one rows is the wrong shape for one answer.
 *
 * It holds identically for the throttle lens, and that is most of why the lens
 * is worth having: an audit that greps for `rate|429`, finds nothing, and files
 * ONE medium finding is doing exactly this, by hand.
 */
export function guardTotals(rows: readonly GuardRow[]): {
  handlers: number;
  unguarded: number;
  fileScoped: number;
  noMarkerAnywhere: boolean;
  /** Unguarded rows whose handler is an authentication endpoint. */
  unguardedLoginShaped: number;
} {
  const unguarded = rows.filter((r) => r.state === "unguarded");
  return {
    handlers: rows.length,
    unguarded: unguarded.length,
    fileScoped: rows.filter((r) => r.scope === "file").length,
    // Not "every row is unguarded" — that is also true of one badly-written
    // route file. It takes a handler population big enough for the absence to
    // be a property of the application rather than of a file.
    noMarkerAnywhere: rows.length >= 3 && unguarded.length === rows.length,
    unguardedLoginShaped: unguarded.filter((r) => r.loginShape).length,
  };
}

export function renderGuardsMd(rows: GuardRow[], context?: string, lens: GuardLens = "auth"): string {
  const t = guardTotals(rows);
  const spec = LENSES[lens];
  const [present, absent, waived] = spec.verdicts;
  const throttling = lens === "throttle";
  const L: string[] = [
    throttling
      ? `# ultrasec throttle matrix (${t.handlers} handler(s), ${t.unguarded} with no visible rate limit)`
      : `# ultrasec guard matrix (${t.handlers} handler(s), ${t.unguarded} with no visible guard)`,
    "",
  ];
  if (throttling) {
    L.push(`Every handler that reads request data, and the rate-limiting/throttling markers visible`);
    L.push(`in its scope. This is the other question the taint pass cannot ask: a missing limit has`);
    L.push(`no line to point at either.`);
  } else {
    L.push(`Every handler that reads request data, and the authentication/authorization markers`);
    L.push(`visible in its scope. This is the question the taint pass cannot ask: a missing`);
    L.push(`authorization check has no line to point at.`);
  }
  L.push("");
  L.push(`For each row set a \`verdict\`:`);
  if (throttling) {
    L.push(`\`${present}\` (a real limit applies) · \`${absent}\` (nothing bounds request volume — a finding) ·`);
    L.push(`\`${waived}\` (idempotent, cheap and non-enumerable — nothing to gain by repeating it).`);
    L.push(`Save as THROTTLE.json (array of {id, verdict, note?}) and run \`ultrasec guards --lens throttle --apply THROTTLE.json\`.`);
  } else {
    L.push(`\`${present}\` (a real check protects it) · \`${absent}\` (nothing does — a finding) ·`);
    L.push(`\`${waived}\` (health check, login, webhook with its own signature check).`);
    L.push(`Save as GUARDS.json (array of {id, verdict, note?}) and run \`ultrasec guards --apply GUARDS.json\`.`);
  }
  L.push("");
  if (throttling) {
    L.push(`> **A marker is a candidate, not a proof.** A \`limiter\` in scope may cover a different`);
    L.push(`> route, count the wrong key, or be configured with a ceiling so high it never fires.`);
    L.push(`> Read the handler. Equally, the limit may live at an ingress, a CDN or an API gateway`);
    L.push(`> this pass cannot see — an \`${absent}\` row is a question, not an accusation.`);
  } else {
    L.push(`> **A marker is a candidate, not a proof.** \`requireAuth\` in scope may guard a`);
    L.push(`> different branch, run after the object is read, or check authentication where the`);
    L.push(`> route needs authorization. Read the handler. Equally, a route can be protected by`);
    L.push(`> framework middleware, an ingress rule or a decorator this pass cannot see — a`);
    L.push(`> \`unguarded\` row is a question, not an accusation.`);
  }
  L.push("");
  if (t.noMarkerAnywhere && throttling) {
    L.push(`## No rate limiting anywhere in this repository`);
    L.push("");
    L.push(`Not one of the ${t.handlers} handlers has a throttling marker in scope, and no marker appears`);
    L.push(`anywhere in the scanned tree. That is **one architectural fact, not ${t.handlers} findings**:`);
    L.push(`either nothing bounds request volume at all, or the limit lives somewhere this scan cannot`);
    L.push(`see — an ingress rule, a CDN, an API gateway, a WAF.`);
    L.push("");
    L.push(`**Answer that question once**, in \`CONTEXT.md\`, before adjudicating the rows below. If a`);
    L.push(`limit does exist outside the repo, say where and say what it counts; a per-IP cap does not`);
    L.push(`stop a distributed attempt and a global cap does not stop one account being ground down.`);
    L.push(`If there is no limit at all, the severity is decided by what the cheapest request costs —`);
    L.push(`an unbounded fan-out to a backend, or a CPU-bound call (see the \`algodos\` findings).`);
    L.push("");
    if (t.unguardedLoginShaped) {
      L.push(`> ⚠️  ${t.unguardedLoginShaped} of those handler(s) look like AUTHENTICATION endpoints. There the absence`);
      L.push(`> is not a capacity problem: it is credential stuffing (CWE-307) and, if the response`);
      L.push(`> distinguishes "no such account" from "wrong password" — in the body, the status or`);
      L.push(`> merely the timing — account enumeration (CWE-204). Read those first, and read what`);
      L.push(`> they answer on a failure, not just whether they are limited.`);
      L.push("");
    }
  } else if (t.noMarkerAnywhere) {
    L.push(`## No authentication mechanism anywhere in this repository`);
    L.push("");
    L.push(`Not one of the ${t.handlers} handlers has an auth marker in scope, and no marker appears`);
    L.push(`anywhere in the scanned tree. That is **one architectural fact, not ${t.handlers} findings**:`);
    L.push(`either the application is public by design (an information site, a docs portal), or its`);
    L.push(`authentication lives somewhere this scan cannot see — an API gateway, an ingress rule, a`);
    L.push(`reverse proxy, a separate BFF.`);
    L.push("");
    L.push(`**Answer that question once**, in \`CONTEXT.md\`, before adjudicating the rows below. If the`);
    L.push(`app is genuinely public, every row is \`intentionally-public\` and this stage is done. If it`);
    L.push(`is not, the guard is outside the repo and the real question is whether anything can reach`);
    L.push(`these handlers directly — bypassing it.`);
    L.push("");
  }
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

  const unguardedAll = rows.filter((r) => r.state === "unguarded");
  // Under the throttle lens the login-shaped handlers are a different, worse
  // finding, so they go first — the order of the worklist is the order someone
  // will actually read it in.
  const unguarded = throttling ? [...unguardedAll.filter((r) => r.loginShape), ...unguardedAll.filter((r) => !r.loginShape)] : unguardedAll;
  const guarded = rows.filter((r) => r.state === "guarded");

  if (unguarded.length) {
    L.push(throttling ? `## No visible rate limit (${unguarded.length}) — read these first` : `## No visible guard (${unguarded.length}) — read these first`);
    L.push("");
    for (const r of unguarded) {
      const shape = throttling && r.loginShape ? ` · **auth endpoint — brute force / account enumeration**` : "";
      L.push(
        `- \`${r.id}\` — \`${r.file}:${r.line}\`${r.handler ? ` in \`${r.handler}()\`` : " (module scope)"} · ${r.kinds.join("/")} · ${r.reads} request read(s)${shape}`,
      );
    }
    L.push("");
  }
  if (guarded.length) {
    L.push(
      throttling
        ? `## A rate limit is visible (${guarded.length}) — confirm it actually applies`
        : `## A guard is visible (${guarded.length}) — confirm it actually applies`,
    );
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
export function guardDiscovery(row: GuardRow, note?: string, lens: GuardLens = "auth"): Discovery {
  const where = row.handler ? `${row.handler}()` : "module scope";
  const scopeWord = row.scope === "symbol" ? "the handler's scope" : "the file";
  const cited = `\`${row.file}:${row.line}\`${row.handler ? ` (\`${row.handler}()\`)` : ""} reads request data (${row.kinds.join("/")}, ${row.reads} read(s))`;

  if (lens === "throttle") {
    // An auth endpoint with no limit is a different bug from a search endpoint
    // with no limit: one is credential stuffing and account enumeration, the
    // other is capacity. Rating them the same would flatten the distinction the
    // lens exists to draw. `medium` for the capacity case matches how a real
    // audit rated it, against an ingress limit nobody in the repo could confirm.
    return {
      title: row.loginShape
        ? `Authentication endpoint with no rate limit: ${where} in ${row.file}`
        : `Request handler with no rate limit: ${where} in ${row.file}`,
      category: "other",
      severity: row.loginShape ? "high" : "medium",
      cwe: row.loginShape ? "CWE-307" : "CWE-770",
      message:
        `${cited} and no rate-limiting or throttling marker is visible in ${scopeWord}. ` +
        (row.loginShape
          ? `The handler's name or path says it authenticates, so unbounded attempts are credential stuffing (CWE-307); if its failure response distinguishes an unknown account from a wrong password — in the body, the status code or the timing — it is also account enumeration (CWE-204). `
          : ``) +
        `Adjudicated \`unthrottled\` against the throttle matrix. A limit enforced outside the repo (ingress, CDN, gateway) refutes this — name it and say what it counts.` +
        (note ? ` ${note}` : ""),
      file: row.file,
      line: row.line,
    };
  }

  return {
    title: `Unauthenticated request handler: ${where} in ${row.file}`,
    category: "authz",
    severity: "high",
    cwe: "CWE-306",
    message:
      `${cited} and no authentication or authorization marker is visible in ${scopeWord}. ` +
      `Adjudicated \`unguarded\` against the guard matrix.` +
      (note ? ` ${note}` : ""),
    file: row.file,
    line: row.line,
  };
}
