import { langForFile, type Sym } from "./lang.js";
import { findSanitizers } from "./catalog.js";
import { SOURCE_SCOPES, type Dataflow, type PathStep, type SourceScope } from "./types.js";
import { enclosingSymbolName } from "./scan.js";

/**
 * Intra-procedural reasoning that sharpens the summary-based BFS in `taint.ts`.
 *
 * The BFS answers "can control reach this sink from a file that reads untrusted
 * input?". That is the right question at call-graph scale, but on its own it is
 * blind to two things a human auditor sees immediately:
 *
 *   1. WHERE in the file the source sits. A `req.query` in `handlerA()` and an
 *      `exec()` in `handlerB()` of the same router share a file and nothing else.
 *   2. WHETHER the value actually travels. `escapeHtml()` two lines above the
 *      sink, or a source whose binding is never mentioned again, both change the
 *      verdict.
 *
 * Everything here is a SIGNAL, never a filter: candidates keep being emitted and
 * the AI adjudicates. The signals feed ranking and the dossier note so the
 * expensive `dossier` reads land on the flows most likely to be real.
 */

// ── Enclosing function units ────────────────────────────────────────────────
//
// The symbol table alone cannot answer "are these two lines in the same
// function?" for the code that matters most. Measured on the project's own
// fixtures, an Express router file extracts ZERO symbols: every handler is an
// anonymous arrow passed to `app.get(...)`, so `enclosingSymbolName` returns
// undefined for the whole file and twenty unrelated handlers look identical.
// That is exactly the shape this signal exists to separate.
//
// So units are recovered from the code's own block structure: the innermost
// enclosing FUNCTION block, ignoring `if`/`for`/`try` blocks (too fine — a source
// outside an `if` still flows into it) and class bodies (too coarse — two methods
// are not one unit). Identity is the block's opening line, which is unique per
// file and needs no name.

/** Block openers that are control flow, not a function. */
const CONTROL_OPEN =
  /^\s*(?:\}\s*)?(?:else\s+)?(?:if|for|while|switch|case|catch|try|do|finally|with|using|lock|unsafe|synchronized|match|loop|unless|begin)\b/;

/** Does this line open a function/method/closure body? */
function opensFunction(text: string): boolean {
  if (CONTROL_OPEN.test(text)) return false;
  if (/=>/.test(text)) return true; // arrow / lambda — the Express handler case
  if (/\b(?:function|func|fn|def|sub|proc)\b/.test(text)) return true;
  // A WRAPPED signature: the brace lands on a continuation line, which is what
  // every Java formatter produces for a long parameter list —
  //     public void doPost(HttpServletRequest request, HttpServletResponse response)
  //             throws ServletException, IOException {
  // Missing this made every such method invisible as a unit, so a whole Java file
  // collapsed to "module" scope and the signal went quiet on the stack it matters
  // most for.
  if (/^\s*(?:\)\s*)?(?:throws\s+[\w.,\s]+|->\s*[^{]*|:\s*[^{]*)?\{\s*$/.test(text) && /[)\w]/.test(text)) return true;
  // `name(args) {`, `void name(args) {`, `name(args): Type {` — a method header.
  return /\)\s*(?:->\s*[^{]+|:\s*[^{]+|const\s*|noexcept\s*|throws\s[^{]+)?\{\s*$/.test(text);
}

/** Strip the line noise that desynchronizes brace counting. Deliberately crude:
 *  a wrong strip costs a misranked candidate, never a dropped one (the map is
 *  discarded wholesale when the file ends unbalanced). */
function stripNoise(text: string, inBlockComment: boolean, hashComments: boolean): { clean: string; inBlockComment: boolean } {
  let out = "";
  let i = 0;
  let block = inBlockComment;
  while (i < text.length) {
    if (block) {
      const end = text.indexOf("*/", i);
      if (end < 0) return { clean: out, inBlockComment: true };
      i = end + 2;
      block = false;
      continue;
    }
    const two = text.slice(i, i + 2);
    if (two === "/*") {
      block = true;
      i += 2;
      continue;
    }
    if (two === "//") break;
    // `#` starts a comment in PHP and nowhere else among the brace languages.
    // Treating it as one everywhere silently broke modern TypeScript: a private
    // METHOD (`#helper() {`) had its opening brace swallowed, the file ended
    // unbalanced, and the whole unit map was discarded — the feature turning
    // itself off on exactly the code it was written for. PHP 8's `#[Attr]` is an
    // attribute, not a comment.
    if (hashComments && text[i] === "#" && text[i + 1] !== "[") break;
    const q = text[i];
    if (q === '"' || q === "'" || q === "`") {
      i++;
      while (i < text.length && text[i] !== q) i += text[i] === "\\" ? 2 : 1;
      i++;
      continue;
    }
    out += text[i];
    i++;
  }
  return { clean: out, inBlockComment: block };
}

const BRACE_LANGS = new Set(["javascript", "java", "go", "rust", "c_cpp", "csharp", "kotlin", "swift", "scala", "php"]);

/**
 * Innermost enclosing function block per line, as a 1-based opening line number
 * (0 = file scope). `ok: false` means the mapping could not be trusted and the
 * caller must fall back to symbol-name comparison.
 */
export interface UnitMap {
  ok: boolean;
  at(line: number): number;
}

const UNKNOWN_UNITS: UnitMap = { ok: false, at: () => 0 };

function braceUnits(lines: string[], hashComments: boolean): UnitMap {
  const units = new Array<number>(lines.length + 1).fill(0);
  const stack: { start: number; isFn: boolean }[] = [];
  let block = false;
  let depth = 0;

  const innermostFn = (): number => {
    for (let i = stack.length - 1; i >= 0; i--) if (stack[i]!.isFn) return stack[i]!.start;
    return 0;
  };

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i]!;
    const { clean, inBlockComment } = stripNoise(raw, block, hashComments);
    block = inBlockComment;
    const before = innermostFn();
    const isFn = opensFunction(raw);
    for (const ch of clean) {
      if (ch === "{") {
        stack.push({ start: i + 1, isFn });
        depth++;
      } else if (ch === "}") {
        stack.pop();
        depth--;
        if (depth < 0) return UNKNOWN_UNITS; // desynchronized — do not guess
      }
    }
    const after = innermostFn();
    // The innermost function seen at ANY point on this line, so both the opening
    // line (`(req,res) => {`) and the closing one attribute to the function.
    units[i + 1] = Math.max(before, after);
  }

  if (depth !== 0) return UNKNOWN_UNITS;
  return { ok: true, at: (l) => units[l] ?? 0 };
}

const PY_DEF = /^(\s*)(?:async\s+)?def\s/;

function pythonUnits(lines: string[]): UnitMap {
  const units = new Array<number>(lines.length + 1).fill(0);
  const stack: { indent: number; start: number }[] = [];
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i]!;
    if (raw.trim() === "" || /^\s*#/.test(raw)) {
      units[i + 1] = stack.length ? stack[stack.length - 1]!.start : 0;
      continue;
    }
    const indent = raw.length - raw.trimStart().length;
    while (stack.length && indent <= stack[stack.length - 1]!.indent) stack.pop();
    const def = PY_DEF.exec(raw);
    units[i + 1] = def ? i + 1 : stack.length ? stack[stack.length - 1]!.start : 0;
    if (def) stack.push({ indent, start: i + 1 });
  }
  return { ok: true, at: (l) => units[l] ?? 0 };
}

/** Build the per-line function-unit map for a file, or an untrusted map when the
 *  language has no supported block model. */
export function buildUnitMap(lines: string[], langId: string): UnitMap {
  if (langId === "python") return pythonUnits(lines);
  if (BRACE_LANGS.has(langId)) return braceUnits(lines, langId === "php");
  return UNKNOWN_UNITS;
}

// ── Source scope ────────────────────────────────────────────────────────────

/**
 * `symbol` is the strongest shape — the flow a human would draw. `module` covers
 * a source at file scope (a middleware body, a top-level route registration):
 * legitimate and common, so it is NOT demoted. `file` means the source lives in a
 * DIFFERENT function of the same file; nothing connects the two beyond
 * co-location, and on a router with twenty handlers that is where quadratic noise
 * comes from.
 *
 * 0 = strongest. A ranking key, never a cut.
 */
export function scopeRank(s: SourceScope | undefined): number {
  const i = SOURCE_SCOPES.indexOf((s ?? "module") as SourceScope);
  return i < 0 ? SOURCE_SCOPES.length : i;
}

/**
 * Classify a source line against the frame's entry line, both in the same file.
 *
 * Prefers the block-derived unit map, which sees anonymous handlers; falls back
 * to symbol-name comparison when the language has no block model or the file
 * ended unbalanced. A source with no enclosing unit is `module` under either
 * mechanism — a top-level `const cfg = process.env.X` genuinely does reach the
 * functions below it.
 */
export function classifySourceScope(symbols: Sym[], sourceLine: number, entryLine: number, units: UnitMap): SourceScope {
  if (units.ok) {
    const src = units.at(sourceLine);
    if (src === 0) return "module";
    return src === units.at(entryLine) ? "symbol" : "file";
  }
  const srcSymbol = enclosingSymbolName(symbols, sourceLine);
  if (srcSymbol === undefined) return "module";
  return srcSymbol === enclosingSymbolName(symbols, entryLine) ? "symbol" : "file";
}

// ── Sanitizers along the whole path ─────────────────────────────────────────

export interface SanitizerHit {
  file: string;
  line: number;
  note: string;
}

/** How many lines above the sink to inspect: sanitization is usually written
 *  immediately before the dangerous call, not on the same line as it. */
const LOOKBEHIND = 3;

/**
 * Collect sanitizer hints along every hop, not just the sink line.
 *
 * Looking only at the sink line — as this used to — misses the ordinary shape of
 * defensive code: `const safe = escapeHtml(raw)` on one line, the sink on the
 * next. That silence reads as "nothing protects this flow", which is exactly the
 * wrong prior to hand an adjudicator.
 *
 * De-duplicated by (file, line, note) and ordered by position so the note reads
 * as a walk down the path. Hints only — they annotate and lower nothing on their
 * own; the adjudicator confirms the sanitizer actually covers THIS flow.
 */
export function sanitizersAlongPath(path: PathStep[], sinkKind: string, lineAt: (file: string, line: number) => string): SanitizerHit[] {
  const out: SanitizerHit[] = [];
  const seen = new Set<string>();
  const sink = path[path.length - 1];

  const inspect = (file: string, line: number): void => {
    if (line < 1) return;
    const lang = langForFile(file);
    if (!lang) return;
    const text = lineAt(file, line);
    if (!text) return;
    for (const note of findSanitizers(lang, text, sinkKind)) {
      const key = `${file}:${line}:${note}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ file, line, note });
    }
  };

  for (const step of path) inspect(step.file, step.line);
  // The lines just above the sink, which no path step points at.
  if (sink) {
    for (let l = sink.line - LOOKBEHIND; l < sink.line; l++) inspect(sink.file, l);
  }

  return out.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.note.localeCompare(b.note));
}

// ── Def-use chaining (intra-procedural) ─────────────────────────────────────

/** Assignment keywords and common type tokens that are never the bound name. */
const NOT_A_BINDING = new Set([
  "const",
  "let",
  "var",
  "final",
  "val",
  "public",
  "private",
  "protected",
  "static",
  "readonly",
  "new",
  "await",
  "return",
  "my",
  "our",
  "dim",
  "set",
]);

const IDENT = /[A-Za-z_$][A-Za-z0-9_$]*/g;

/**
 * Find the assignment operator that binds the expression at `atIndex`, i.e. the
 * last `=` / `:=` / `<-` strictly before it that is not part of a comparison
 * (`==`, `===`, `!=`, `<=`, `>=`, `=>`). Returns -1 when the expression is used
 * inline rather than bound.
 */
function bindingOperatorBefore(line: string, atIndex: number): number {
  for (let i = Math.min(atIndex, line.length) - 1; i >= 0; i--) {
    if (line[i] !== "=") continue;
    const prev = line[i - 1] ?? "";
    const next = line[i + 1] ?? "";
    if (next === "=" || next === ">") continue; // ==, ===, =>
    if (prev === "=" || prev === "!" || prev === "<" || prev === ">" || prev === "+" || prev === "-" || prev === "*" || prev === "/") continue;
    return i;
  }
  return -1;
}

/**
 * Names bound by the left-hand side of an assignment.
 *
 * Destructuring (`const { id, name } = req.body`) binds every identifier inside
 * the pattern; a plain binding (`String uid = req.getParameter(..)`) binds the
 * LAST identifier, which skips type tokens without needing a per-language type
 * vocabulary. `this.userId = …` yields `userId`, which is what later
 * word-boundary matching wants — `this.userId` contains it.
 */
export function boundNames(lhs: string): string[] {
  const names: string[] = [];
  const destructured = /[{[]/.test(lhs);
  const idents = lhs.match(IDENT) ?? [];
  if (destructured) {
    for (const id of idents) if (!NOT_A_BINDING.has(id)) names.push(id);
  } else {
    const last = idents[idents.length - 1];
    if (last && !NOT_A_BINDING.has(last)) names.push(last);
  }
  return [...new Set(names)];
}

function mentions(line: string, name: string): boolean {
  return new RegExp(`(?<![A-Za-z0-9_$])${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![A-Za-z0-9_$])`).test(line);
}

/**
 * Does the value read at `sourceLine` still reach `entryLine`?
 *
 * A deliberately small forward def-use walk inside one file: seed the tainted
 * set with whatever the source expression is bound to, extend it through
 * assignments that mention a tainted name, then ask whether the entry line
 * mentions one. For the seed frame `entryLine` IS the sink line, so this asks the
 * question directly; for a caller frame it asks whether the value reaches the
 * call that leads to the sink — the same question one hop out.
 *
 * Returns `undefined` when the shape is outside what a line-based walk can
 * decide (an inline use several lines away, a value threaded through an object
 * or a template). Unknown is reported as unknown: an `unlinked` verdict must mean
 * "looked and did not find it", never "could not look".
 */
export function traceDefUse(lines: string[], sourceLine: number, sourceMatch: string, entryLine: number): Dataflow | undefined {
  return traceDefUseDetail(lines, sourceLine, sourceMatch, entryLine).verdict;
}

/**
 * As `traceDefUse`, but also returns the NAMES the walk was following.
 *
 * The verdict alone says "the bound value is not mentioned at the sink"; the
 * names say WHICH value should have arrived, which is what turns the signal from
 * a hint into something an adjudicator can check against the code in front of
 * them. Surfaced in the dossier, never acted on by the engine.
 */
export function traceDefUseDetail(
  lines: string[],
  sourceLine: number,
  sourceMatch: string,
  entryLine: number,
): { verdict: Dataflow | undefined; tainted: string[] } {
  const none = { verdict: undefined, tainted: [] as string[] };
  if (sourceLine > entryLine) return none;
  const srcText = lines[sourceLine - 1] ?? "";
  if (sourceLine === entryLine) return { verdict: "linked", tainted: [] }; // the source expression is ON the line

  const at = srcText.indexOf(sourceMatch);
  const op = bindingOperatorBefore(srcText, at < 0 ? srcText.length : at);
  if (op < 0) return none; // used inline, nothing to follow
  const tainted = new Set(boundNames(srcText.slice(0, op)));
  if (!tainted.size) return none;

  for (let l = sourceLine + 1; l < entryLine; l++) {
    const text = lines[l - 1] ?? "";
    if (![...tainted].some((n) => mentions(text, n))) continue;
    const assign = bindingOperatorBefore(text, text.length);
    if (assign < 0) continue;
    for (const n of boundNames(text.slice(0, assign))) tainted.add(n);
  }

  const target = lines[entryLine - 1] ?? "";
  const names = [...tainted].sort();
  return { verdict: names.some((n) => mentions(target, n)) ? "linked" : "unlinked", tainted: names };
}
