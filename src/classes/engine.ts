import { readText, walk, type RepoTree } from "../walk.js";
import { langForFile } from "../lang.js";
import { codeOfLine } from "../catalog.js";
import type { Finding } from "../types.js";
import { makeToolFinding } from "../tools/normalize.js";
import { WEBCONFIG_SHAPES } from "../webconfig.js";
import { AUTH_SHAPES } from "../authtokens.js";
import { CLASSES } from "./registry.js";
import { PACKS } from "./packs/index.js";
import type { AbsentRule, ClassId, EmitShape, FileRule, FrameworkScope, LineRule, Pack, RouteQueryRule, Rule } from "./types.js";

// The one engine every pack runs on.
//
// It knows four rule KINDS — an unsafe line, a file that never guards what it
// produces, an unbounded query in an export route, a protection that is
// absent — and nothing about any framework. A pack is data; this file applies
// it. Same contract as the detectors it replaced (src/webconfig.ts,
// src/authtokens.ts): a line/statement scan, zero dependencies, every finding a
// CANDIDATE grounded on a resolvable [file:line].

/** One rule firing — the class it proves and the pack it came from. */
export interface ClassHit {
  classId: ClassId;
  packId: string;
  ruleId: string;
  file: string;
  line: number;
}

export interface ClassAuditResult {
  findings: Finding[];
  hits: ClassHit[];
}

/** A rule with the pack and class it was declared under. */
interface BoundRule {
  pack: Pack;
  classId: ClassId;
  rule: Rule;
}

/** Notebooks and stubs keep their language for the taint walk, but none of
 *  these idioms is written in one — and the detectors this engine replaced
 *  never read them. */
const SKIPPED_EXTS = new Set(["ipynb", "pyi"]);

const LEGACY_PREFIX: Record<EmitShape["family"], string> = { webconfig: "Web misconfig — ", authtokens: "Auth token — ", class: "Weakness — " };

/** Every rule of every pack, flattened once. */
export function boundRules(packs: readonly Pack[] = PACKS): BoundRule[] {
  const out: BoundRule[] = [];
  for (const pack of packs)
    for (const [classId, cov] of Object.entries(pack.classes)) {
      if (!cov || !("rules" in cov)) continue;
      for (const rule of cov.rules) out.push({ pack, classId: classId as ClassId, rule });
    }
  return out;
}

/** The shape a rule reports under: its legacy shape when it names one, else the class's. */
export function shapeFor(classId: ClassId, rule: Rule): EmitShape {
  if (rule.emit) {
    const [family, id] = rule.emit.split("/") as [string, string];
    if (family === "webconfig") {
      const s = WEBCONFIG_SHAPES[id];
      if (s) return { family, id: s.id, title: s.title, severity: s.severity, cwe: s.cwe, category: "config", note: s.note };
    }
    if (family === "authtokens") {
      const s = AUTH_SHAPES[id];
      if (s) return { family, id: s.id, title: s.title, severity: s.severity, cwe: s.cwe, category: s.category, note: s.note };
    }
    throw new Error(`classes: rule ${rule.id} emits unknown shape ${rule.emit}`);
  }
  const c = CLASSES[classId];
  return { family: "class", id: c.id, title: c.title, severity: c.severity, cwe: c.cwe, category: c.category, note: rule.note ?? c.note };
}

function hit(rel: string, line: number, shape: EmitShape, evidence: string): Finding {
  return makeToolFinding({
    tool: "ultrasec",
    category: shape.category,
    ident: `${shape.family}:${shape.id}:${rel}:${line}`,
    title: `${LEGACY_PREFIX[shape.family]}${shape.title}`,
    severity: shape.severity,
    message: `${shape.note}\n\nEvidence: \`${evidence.trim().slice(0, 160)}\``,
    file: rel,
    line,
    cwe: shape.cwe,
  });
}

function extOf(rel: string): string {
  const i = rel.lastIndexOf(".");
  return i === -1 ? "" : rel.slice(i + 1).toLowerCase();
}

function lineOf(content: string, index: number): number {
  let n = 1;
  for (let i = 0; i < index && i < content.length; i++) if (content[i] === "\n") n++;
  return n;
}

const dirOfRel = (rel: string): string => (rel.includes("/") ? rel.slice(0, rel.lastIndexOf("/") + 1) : "");

/** Lines of one file: raw text, comment-free code, and which lines are comment only. */
interface FileView {
  rel: string;
  lang: string;
  content: string;
  raw: string[];
  code: string[];
  comment: boolean[];
  codeText: string;
}

function view(rel: string, lang: string, content: string): FileView {
  const raw = content.split(/\r?\n/);
  const hash = lang === "python" || lang === "ruby" || lang === "shell" || lang === "elixir";
  const code = raw.map((t) => codeOfLine(t, lang));
  // A line with no code left, or the inside of a `/* … */` block (`* text`).
  const comment = code.map((c) => c.trim() === "" || (!hash && /^\s*\*/.test(c)));
  return { rel, lang, content, raw, code, comment, codeText: code.map((c, i) => (comment[i] ? "" : c)).join("\n") };
}

function runLine(v: FileView, r: LineRule, emit: (line: number, evidence: string) => void): void {
  if (r.fileGate && !r.fileGate.test(v.content)) return;
  for (let i = 0; i < v.raw.length; i++) {
    if (v.comment[i]) continue;
    const c = v.code[i]!;
    if (!r.match.test(c) || r.unless?.test(c)) continue;
    if (r.context) {
      let seen = false;
      for (let j = Math.max(0, i - r.context.before); j <= i && !seen; j++) seen = !v.comment[j] && r.context.re.test(v.code[j]!);
      if (!seen) continue;
    }
    emit(i + 1, v.raw[i]!);
  }
}

function runFile(v: FileView, r: FileRule, emit: (line: number, evidence: string) => void): void {
  if (!r.gate.every((g) => g.test(v.content))) return;
  if (r.unless?.test(v.codeText)) return;
  let at = -1;
  for (let i = 0; i < v.raw.length; i++) {
    if (v.comment[i] || !r.anchor.test(v.code[i]!)) continue;
    at = i;
    if (r.pick === "first") break;
  }
  if (at >= 0) emit(at + 1, v.raw[at]!);
}

const MAX_STATEMENT = 2000;

/** The statement starting at `start`, ended the way the rule says statements end. */
function statementAt(content: string, start: number, mode: RouteQueryRule["statement"]): string {
  const rest = content.slice(start, start + MAX_STATEMENT);
  if (mode === "js-legacy") {
    const end = rest.search(/;|\n\s*\n/);
    return end === -1 ? rest : rest.slice(0, end);
  }
  let depth = 0;
  let quote: string | null = null;
  for (let i = 0; i < rest.length; i++) {
    const ch = rest[i]!;
    if (quote) {
      if (ch === "\\") i++;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") quote = ch;
    else if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") depth = Math.max(0, depth - 1);
    else if (ch === ";" && depth === 0) return rest.slice(0, i);
    else if (ch === "\n" && depth === 0 && !/^\s*(?:\.|->)/.test(rest.slice(i + 1, i + 200))) return rest.slice(0, i);
  }
  return rest;
}

function isExportRoute(v: FileView, r: RouteQueryRule): boolean {
  if (r.routeFile?.test(v.rel) && r.exportPath.test(v.rel)) return true;
  if (!r.routeDecl) return false;
  for (let i = 0; i < v.code.length; i++) {
    if (v.comment[i]) continue;
    const m = r.routeDecl.exec(v.code[i]!);
    if (m?.[1] && r.exportPath.test(m[1])) return true;
  }
  return false;
}

function runRouteQuery(v: FileView, r: RouteQueryRule, emit: (line: number, evidence: string) => void): void {
  if (!isExportRoute(v, r)) return;
  for (const q of r.queries) {
    const re = new RegExp(q.start.source, q.start.flags.includes("g") ? q.start.flags : `${q.start.flags}g`);
    for (const m of v.content.matchAll(re)) {
      const start = m.index ?? 0;
      const ln = lineOf(v.content, start);
      if (v.comment[ln - 1]) continue;
      const stmt = statementAt(v.content, start, r.statement);
      if (q.requires && !q.requires.test(stmt)) continue;
      if (q.bounded.test(stmt)) continue;
      emit(ln, stmt.split("\n")[0]!);
    }
  }
}

/** An `absent` rule that anchored, waiting for the whole tree to be seen. */
interface Pending {
  bound: BoundRule;
  rel: string;
  line: number;
  evidence: string;
  root: string;
}

/** The directory an absence is judged over: the framework's package when the
 *  file sits in one, the anchor's own directory otherwise. */
function packageRoot(rel: string, frameworks: readonly FrameworkScope[]): string {
  let best: string | undefined;
  for (const f of frameworks) {
    const d = f.dir ? `${f.dir}/` : "";
    if (rel.startsWith(d) && (best === undefined || d.length > best.length)) best = d;
  }
  return best ?? dirOfRel(rel);
}

function frameworkAt(rel: string, id: string, frameworks: readonly FrameworkScope[]): boolean {
  return frameworks.some((f) => f.id === id && (f.dir === "" || rel.startsWith(`${f.dir}/`)));
}

/**
 * Run every pack over the repository. `frameworks` (from `detectFrameworks`)
 * gates the rules that require one and scopes the package-wide absences; it is
 * optional, and every rule that needs neither runs without it.
 */
export function auditWeaknessClasses(
  repo: string,
  prune?: (rel: string) => boolean,
  tree?: RepoTree,
  frameworks: readonly FrameworkScope[] = [],
  packs: readonly Pack[] = PACKS,
): ClassAuditResult {
  const rules = boundRules(packs);
  const read = tree?.read ?? readText;
  const findings: Finding[] = [];
  const hits: ClassHit[] = [];
  const seen = new Set<string>();
  const pending: Pending[] = [];
  // For every `absent` rule with a tree-wide presence test: the directories of
  // the files where the protection was seen.
  const presentDirs = new Map<BoundRule, string[]>();

  const record = (b: BoundRule, rel: string, line: number, evidence: string): void => {
    const shape = shapeFor(b.classId, b.rule);
    const f = hit(rel, line, shape, evidence);
    hits.push({ classId: b.classId, packId: b.pack.id, ruleId: b.rule.id, file: rel, line });
    if (seen.has(f.id)) return;
    seen.add(f.id);
    findings.push(f);
  };

  for (const wf of tree?.files ?? walk(repo)) {
    if (prune?.(wf.rel)) continue;
    const ext = extOf(wf.rel);
    if (SKIPPED_EXTS.has(ext)) continue;
    const lang = langForFile(wf.rel)?.id;
    if (!lang) continue;
    const forFile = rules.filter((b) => b.rule.languages.includes(lang) && (!b.rule.files || b.rule.files.test(wf.rel)));
    const treeChecks = rules.filter(
      (b) =>
        b.rule.kind === "absent" &&
        b.rule.presentInTree &&
        (!b.rule.presentInTree.languages || b.rule.presentInTree.languages.includes(lang)) &&
        (!b.rule.presentInTree.files || b.rule.presentInTree.files.test(wf.rel)),
    );
    if (!forFile.length && !treeChecks.length) continue;
    const content = read(wf.abs);
    if (!content) continue;
    const v = view(wf.rel, lang, content);

    for (const b of treeChecks) {
      const r = b.rule as AbsentRule;
      if (r.presentInTree!.re.test(v.codeText)) (presentDirs.get(b) ?? presentDirs.set(b, []).get(b)!).push(dirOfRel(v.rel));
    }

    for (const b of forFile) {
      const r = b.rule;
      if (r.requiresFramework && !frameworkAt(v.rel, r.requiresFramework, frameworks)) continue;
      const emit = (line: number, evidence: string) => record(b, v.rel, line, evidence);
      if (r.kind === "line") runLine(v, r, emit);
      else if (r.kind === "file") runFile(v, r, emit);
      else if (r.kind === "route-query") runRouteQuery(v, r, emit);
      else {
        if (r.fileGate && !r.fileGate.test(v.content)) continue;
        if (r.presentInFile?.test(v.codeText)) continue;
        let at = v.code.findIndex((c, i) => !v.comment[i] && r.anchor.test(c));
        if (at < 0 && r.fallbackLine1) at = 0;
        if (at < 0) continue;
        if (!r.presentInTree) emit(at + 1, v.raw[at]!);
        else
          pending.push({
            bound: b,
            rel: v.rel,
            line: at + 1,
            evidence: v.raw[at]!,
            root: r.presentInTree.scope === "package" ? packageRoot(v.rel, frameworks) : dirOfRel(v.rel),
          });
      }
    }
  }

  // An absence is only an absence once the whole app has been read: the
  // protection may sit in any file of the app's own tree (middleware, a helper,
  // the config itself) — but a sibling app's does not count.
  for (const p of pending) {
    if ((presentDirs.get(p.bound) ?? []).some((d) => d.startsWith(p.root))) continue;
    record(p.bound, p.rel, p.line, p.evidence);
  }
  return { findings, hits };
}
