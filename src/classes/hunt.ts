import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Manifest } from "../types.js";
import type { AttackSurface } from "../map.js";
import type { InvestigateRegion } from "../investigate.js";
import { citationProblem } from "../investigate.js";
import { badField, describeValue, notInVocabulary, type DroppedRow } from "../apply-parse.js";
import { byStr } from "../util.js";
import { CLASSES } from "./registry.js";
import { huntId, needsHunt, PACK_SUGGESTIONS_FILE, type ClassCoverageCell } from "./coverage.js";
import { CLASS_IDS, type ClassExample, type ClassId } from "./types.js";

// The AI half of the weakness classes.
//
// A pack only knows the idioms someone wrote down. For a class × framework no
// pack covers — no pack for the framework, or a version outside the range the
// pack was validated on — `investigate` emits a HUNT: the class's invariant,
// its guard, examples in the framework's language, the framework and version,
// and the files where the framework lives. The auditor hunts the repository's
// own idioms and returns two things:
//
//   • Discoveries — through the existing ingest (citation checked, duplicates
//     folded, then verify/check like any candidate);
//   • idioms — the unsafe call and the guard as THIS codebase writes them,
//     citation checked too, written to PACK-SUGGESTIONS.json.
//
// A suggestion is never applied. A maintainer promotes it into pack data with
// a vulnerable/fixed fixture and a recall-matrix cell (docs/weakness-classes.md)
// — that is how the packs keep up with frameworks without the engine guessing.

/** The class-hunt payload of an investigate worklist item. */
export interface ClassHunt {
  id: string;
  class: ClassId;
  title: string;
  cwe: string;
  framework: string;
  ecosystem: string;
  version?: string;
  /** Package directory (`""` = repo root). */
  dir: string;
  /** Why the packs do not settle this cell. */
  reason: string;
  /** Packs whose rules already ran on it (a floor, not a verdict). */
  packsApplied: string[];
  invariant: string;
  guard: string;
  rubric: string;
  examples: ClassExample[];
}

/** The language an ecosystem's examples are shown in first. */
const ECOSYSTEM_LANGUAGE: Record<string, string> = { node: "javascript", python: "python", java: "java", go: "go", ruby: "ruby", php: "php" };

const MAX_HUNT_FILES = 8;
const MAX_EXAMPLES = 3;

function huntPrompt(h: ClassHunt): string {
  return (
    `Weakness class \`${h.class}\` (${h.cwe}) on ${h.framework}${h.version ? ` ${h.version}` : ""}${h.dir ? ` in \`${h.dir}\`` : ""} — ${h.reason}. ` +
    `INVARIANT: ${CLASSES[h.class].invariant} A VALID GUARD: ${CLASSES[h.class].guard} ` +
    `Find how THIS repository writes the class with ${h.framework} — its own helpers, middlewares, config and wrappers — and check every place the invariant can break. ` +
    `Each break is a Discovery (cite a resolvable [file:line], set "hunt": "${h.id}"). Each idiom you recognize — the unsafe call AND the guard the code relies on — ` +
    `goes to \`idioms[]\` ({hunt, class, framework, kind: unsafe|guard, pattern, regex?, file, line, note}) so a maintainer can turn it into pack data. ` +
    `Looked and found nothing? Put "${h.id}" in \`hunted[]\` — an empty result is a result.`
  );
}

/** One hunt per class × framework cell no pack settles, in matrix order. */
export function buildClassHunts(manifest: Pick<Manifest, "weaknessClasses" | "frameworks">, surface?: AttackSurface): InvestigateRegion[] {
  const cells: ClassCoverageCell[] = (manifest.weaknessClasses ?? []).filter(needsHunt);
  const out: InvestigateRegion[] = [];
  for (const cell of cells) {
    const cls = CLASSES[cell.class];
    const fw = manifest.frameworks?.find((f) => f.id === cell.framework && f.dir === cell.dir);
    const lang = ECOSYSTEM_LANGUAGE[cell.ecosystem];
    const examples = [...cls.examples].sort((a, b) => Number(b.language === lang) - Number(a.language === lang)).slice(0, MAX_EXAMPLES);
    const prefix = cell.dir ? `${cell.dir}/` : "";
    // Where the framework lives: its manifest line first, then the package's
    // highest-attack-surface files.
    const files = [...(fw ? [fw.evidence.replace(/:\d+$/, "")] : []), ...(surface?.byFile ?? []).map((f) => f.file).filter((f) => f.startsWith(prefix))];
    const hunt: ClassHunt = {
      id: huntId(cell),
      class: cell.class,
      title: cls.title,
      cwe: cls.cwe,
      framework: cell.framework,
      ecosystem: cell.ecosystem,
      ...(cell.version ? { version: cell.version } : {}),
      dir: cell.dir,
      reason: cell.degraded ?? "no pack covers this class here",
      packsApplied: cell.packs,
      invariant: cls.invariant,
      guard: cls.guard,
      rubric: cls.rubric,
      examples,
    };
    out.push({
      region: hunt.id,
      score: 0,
      sinks: 0,
      sources: 0,
      files: [...new Set(files)].slice(0, MAX_HUNT_FILES),
      neighbors: [],
      prompt: huntPrompt(hunt),
      hunt,
    });
  }
  return out;
}

// ── Ingest: idioms and hunted cells ─────────────────────────────────────────

/** One idiom the auditor recognized, as submitted in INVESTIGATE.json `idioms[]`. */
export interface IdiomRow {
  hunt?: string;
  class: ClassId;
  framework: string;
  kind: "unsafe" | "guard";
  language?: string;
  /** The idiom as it reads in the code. */
  pattern: string;
  /** A proposed matcher; must compile. */
  regex?: string;
  file: string;
  line: number;
  note?: string;
}

export interface HuntResults {
  idioms: IdiomRow[];
  hunted: string[];
  dropped: DroppedRow[];
}

const HUNT_ID = /^hunt:[a-z-]+:[\w.-]+(?:@.+)?$/;
const IDIOM_KINDS = ["unsafe", "guard"] as const;

function parseIdiom(raw: unknown): { row?: IdiomRow; reason?: string } {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return { reason: badField("idiom", raw, "an object") };
  const d = raw as Record<string, unknown>;
  const bad: string[] = [];
  if (!(CLASS_IDS as readonly string[]).includes(d.class as string)) bad.push(notInVocabulary("class", d.class, CLASS_IDS));
  if (!(IDIOM_KINDS as readonly string[]).includes(d.kind as string)) bad.push(notInVocabulary("kind", d.kind, IDIOM_KINDS));
  for (const field of ["framework", "pattern", "file"] as const) {
    if (typeof d[field] !== "string" || !(d[field] as string).trim()) bad.push(badField(field, d[field], "a non-empty string"));
  }
  if (!Number.isInteger(d.line) || (d.line as number) < 1) bad.push(badField("line", d.line, "an integer ≥ 1"));
  if (d.hunt !== undefined && (typeof d.hunt !== "string" || !HUNT_ID.test(d.hunt)))
    bad.push(badField("hunt", d.hunt, "a worklist hunt id (hunt:<class>:<framework>[@dir])"));
  if (d.regex !== undefined) {
    if (typeof d.regex !== "string") bad.push(badField("regex", d.regex, "a string"));
    else
      try {
        new RegExp(d.regex);
      } catch {
        bad.push(`regex ${describeValue(d.regex)} does not compile`);
      }
  }
  if (bad.length) return { reason: bad.join(", ") };
  return {
    row: {
      ...(typeof d.hunt === "string" ? { hunt: d.hunt } : {}),
      class: d.class as ClassId,
      framework: (d.framework as string).trim(),
      kind: d.kind as IdiomRow["kind"],
      ...(typeof d.language === "string" ? { language: d.language } : {}),
      pattern: (d.pattern as string).trim(),
      ...(typeof d.regex === "string" ? { regex: d.regex } : {}),
      file: d.file as string,
      line: d.line as number,
      ...(typeof d.note === "string" ? { note: d.note } : {}),
    },
  };
}

/**
 * Read the class-hunt half of an INVESTIGATE.json: `idioms[]`, `hunted[]`,
 * and the `hunt` ids discoveries carry. A bare Discovery[] array has neither
 * and yields nothing — the format stays backward compatible.
 */
export function parseHuntResults(raw: string): HuntResults {
  const data = JSON.parse(raw) as unknown;
  const out: HuntResults = { idioms: [], hunted: [], dropped: [] };
  if (!data || typeof data !== "object") return out;
  const obj = data as Record<string, unknown>;
  const discoveries = Array.isArray(data) ? data : Array.isArray(obj.discoveries) ? obj.discoveries : [];
  for (const d of discoveries) {
    const h = (d as { hunt?: unknown } | null)?.hunt;
    if (typeof h === "string" && HUNT_ID.test(h)) out.hunted.push(h);
  }
  if (Array.isArray(data)) return out;
  for (const h of Array.isArray(obj.hunted) ? obj.hunted : []) if (typeof h === "string" && HUNT_ID.test(h)) out.hunted.push(h);
  for (const [index, row] of (Array.isArray(obj.idioms) ? obj.idioms : []).entries()) {
    const p = parseIdiom(row);
    if (p.row) {
      out.idioms.push(p.row);
      if (p.row.hunt) out.hunted.push(p.row.hunt);
    } else out.dropped.push({ index, reason: `idioms[${index}]: ${p.reason}` });
  }
  return out;
}

/** An INVESTIGATE.json that carries only hunt results (no `discoveries` key). */
export function isHuntOnlyPayload(data: unknown): boolean {
  if (!data || typeof data !== "object" || Array.isArray(data)) return false;
  const o = data as Record<string, unknown>;
  return !Array.isArray(o.discoveries) && (Array.isArray(o.idioms) || Array.isArray(o.hunted));
}

/** A suggestion as stored in PACK-SUGGESTIONS.json. */
export interface PackSuggestion extends IdiomRow {
  /** The cited line, as read when the suggestion was recorded. */
  evidence: string;
  /** The framework version the idiom was seen on, from the manifest. */
  seenOn?: string;
  /** The pack it would extend (`new pack` when the framework has none). */
  pack: string;
}

export interface PackSuggestionsFile {
  schema: 1;
  note: string;
  hunted: string[];
  suggestions: PackSuggestion[];
}

const SUGGESTIONS_NOTE =
  "Proposals recognized by the AI hunt. The engine NEVER applies them: a maintainer promotes one by adding it to a pack in src/classes/packs with a vulnerable and a fixed fixture and a recall-matrix cell — see docs/weakness-classes.md.";

export interface RecordResult {
  accepted: number;
  rejected: { idiom: IdiomRow; reason: string }[];
  hunted: string[];
  path?: string;
}

/**
 * Fold hunt results into the run's PACK-SUGGESTIONS.json. Idioms whose
 * citation does not resolve are rejected exactly like a discovery's would be;
 * the rest are merged with what earlier applies recorded (deduplicated, never
 * dropped). Nothing is written when there is nothing to record.
 */
export function recordHuntResults(
  run: string,
  repo: string,
  manifest: Pick<Manifest, "frameworks">,
  results: readonly HuntResults[],
  packIds: readonly string[],
): RecordResult {
  const path = join(run, PACK_SUGGESTIONS_FILE);
  const rejected: RecordResult["rejected"] = [];
  const fresh: PackSuggestion[] = [];
  const hunted = new Set<string>();
  for (const r of results) {
    for (const h of r.hunted) hunted.add(h);
    for (const idiom of r.idioms) {
      const problem = citationProblem(repo, { file: idiom.file, line: idiom.line });
      if (problem) {
        rejected.push({ idiom, reason: problem });
        continue;
      }
      const text = readFileSync(join(repo, idiom.file), "utf8").split(/\r?\n/)[idiom.line - 1] ?? "";
      const fw = manifest.frameworks?.find((f) => f.id === idiom.framework);
      fresh.push({
        ...idiom,
        evidence: text.trim().slice(0, 200),
        ...(fw?.version ? { seenOn: `${fw.id} ${fw.version}` } : {}),
        pack: packIds.includes(idiom.framework) ? idiom.framework : `new pack: ${idiom.framework}`,
      });
    }
  }
  if (!fresh.length && !hunted.size) return { accepted: 0, rejected, hunted: [] };

  let prior: PackSuggestionsFile = { schema: 1, note: SUGGESTIONS_NOTE, hunted: [], suggestions: [] };
  if (existsSync(path)) {
    try {
      const p = JSON.parse(readFileSync(path, "utf8")) as Partial<PackSuggestionsFile>;
      prior = { ...prior, hunted: p.hunted ?? [], suggestions: p.suggestions ?? [] };
    } catch {
      /* an unreadable file is replaced by what this apply knows, not merged into */
    }
  }
  const key = (s: PackSuggestion) => [s.class, s.framework, s.kind, s.pattern, s.file, s.line].join("\0");
  const merged = new Map(prior.suggestions.map((s) => [key(s), s]));
  let accepted = 0;
  for (const s of fresh)
    if (!merged.has(key(s))) {
      merged.set(key(s), s);
      accepted++;
    }
  const file: PackSuggestionsFile = {
    schema: 1,
    note: SUGGESTIONS_NOTE,
    hunted: [...new Set([...prior.hunted, ...hunted])].sort(byStr),
    suggestions: [...merged.values()].sort((a, b) => byStr(a.class, b.class) || byStr(a.framework, b.framework) || byStr(a.file, b.file) || a.line - b.line),
  };
  writeFileSync(path, JSON.stringify(file, null, 2) + "\n");
  return { accepted, rejected, hunted: [...hunted].sort(byStr), path };
}
