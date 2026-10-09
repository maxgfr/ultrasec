import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { readPath } from "../runlayout.js";
import { readInvestigateTodo } from "../investigate.js";
import type { DetectedFramework } from "../frameworks.js";
import { satisfies } from "../frameworks.js";
import { CLASS_LIST, MATRIX_ROWS } from "./registry.js";
import { PACKS } from "./packs/index.js";
import { CATALOG_ROW, type ClassId, type MatrixRowId, type Pack } from "./types.js";
import { languagesOf } from "../stack.js";
import { catalogIdioms, genericRequestSources, type CatalogIdiom } from "../catalog.js";

// The weakness-class × framework matrix — which detected framework each class
// was matched for by a pack, which it was hunted for by the AI, and which
// nobody looked at.
//
// A column is a web framework of the stack table, or a web framework the
// table does not know but the package's code shows (`inferred`). Every class
// gets a cell in every column: a framework with no pack, in an ecosystem with
// no pack, is not an empty column — it is a column of cells to hunt.
//
// A pack is only a claim inside the version range it was validated against.
// So a cell is DEGRADED when the framework has no pack (only language idioms
// applied), when the framework's version is outside its pack's `testedWith`
// (the WHOLE column: a language idiom is no better tested on a framework
// release nobody ran it against, and the framework may now hand the code its
// input differently), or when a library pack's rules decided the cell and the
// library's version is outside the library pack's range. The rules still ran —
// a floor is better than nothing — but the cell says so, and the `investigate`
// worklist hunts it.
//
// One more row than there are classes: `taint-catalog`, the catalog's own
// framework idioms (request inputs, route conventions, sink refutations) —
// labelled with a framework and a version range in src/catalog.ts. A column
// whose framework the catalog knows only at other versions, or not at all, is
// degraded there and hunted: every taint class is blind to an input API the
// catalog cannot see.
//
// Nothing in this file names a framework: columns come from the stack table,
// claims from pack data and catalog labels.

export const CLASS_CELL_STATES = ["deterministic", "not-applicable", "not-covered", "ai-hunt", "ai-hunted"] as const;
export type ClassCellState = (typeof CLASS_CELL_STATES)[number];

export interface ClassCoverageCell {
  /** A weakness class, or the `taint-catalog` row. */
  class: MatrixRowId;
  framework: string;
  ecosystem: string;
  /** Package directory of the framework (`""` = repo root). */
  dir: string;
  version?: string;
  state: ClassCellState;
  /** Packs whose rules ran for this cell. */
  packs: string[];
  /** Why the deterministic coverage cannot be trusted as-is (no framework pack, version out of range). */
  degraded?: string;
  /** Why the class does not apply (from the pack's `notApplicable`). */
  reason?: string;
}

/** Where `investigate --apply` writes the idioms the AI recognized. */
export const PACK_SUGGESTIONS_FILE = "PACK-SUGGESTIONS.json";

/** The worklist id of the AI hunt for one cell — stable across runs. */
export function huntId(cell: Pick<ClassCoverageCell, "class" | "framework" | "dir">): string {
  return `hunt:${cell.class}:${cell.framework}${cell.dir ? `@${cell.dir}` : ""}`;
}

/** A cell the deterministic packs do not settle, and the AI should hunt. */
export function needsHunt(cell: ClassCoverageCell): boolean {
  return cell.state !== "not-applicable" && (cell.state !== "deterministic" || cell.degraded !== undefined);
}

/** A pack's coverage of one class, if it has any rule that reads one of `languages`. */
function rulesFor(p: Pack, c: ClassId, languages: readonly string[]): boolean {
  const cov = p.classes[c];
  return !!cov && "rules" in cov && cov.rules.some((r) => r.languages.some((l) => languages.includes(l)));
}

/** Does a pack hold any rule reading one of `languages`? */
function readsAny(p: Pack, languages: readonly string[]): boolean {
  return Object.keys(p.classes).some((c) => rulesFor(p, c as ClassId, languages));
}

/** A library belongs to a column when one package holds the other (or they are the same). */
const nests = (a: string, b: string): boolean => a === b || a === "" || b === "" || b.startsWith(`${a}/`) || a.startsWith(`${b}/`);

const outside = (f: DetectedFramework, p: Pack): string | undefined =>
  p.testedWith && f.version && !satisfies(f.version, p.testedWith) ? `${f.title} ${f.version} is outside ${p.id} testedWith ${p.testedWith}` : undefined;

/** The libraries declared in a framework's package (or one holding it), in its language. */
function attachedLibraries(f: DetectedFramework, libraries: readonly DetectedFramework[]): DetectedFramework[] {
  const languages = languagesOf(f);
  return libraries.filter((l) => nests(l.dir, f.dir) && languages.some((x) => languagesOf(l).includes(x)));
}

/** The `taint-catalog` cell of one column: the catalog rows labelled for the
 *  framework or its libraries, checked against their versions. */
function catalogCell(f: DetectedFramework, libs: readonly DetectedFramework[], idioms: readonly CatalogIdiom[]): ClassCoverageCell {
  const base = { class: CATALOG_ROW, framework: f.id, ecosystem: f.ecosystem, dir: f.dir, ...(f.version ? { version: f.version } : {}) };
  const languages = languagesOf(f);
  const owners = f.kind === "inferred" ? libs : [f, ...libs];
  const mine = idioms.filter((i) => owners.some((o) => o.id === i.framework));
  if (!mine.length) {
    const generic = languages.filter((l) => genericRequestSources(l).length);
    const noLabel = f.kind === "inferred" ? `${f.title} — no catalog row can know it` : `no ${f.title} input or route idiom in the taint catalog`;
    return generic.length
      ? { ...base, state: "deterministic", packs: ["catalog"], degraded: `${noLabel} — only the generic ${generic.join("/")} request shapes` }
      : { ...base, state: "not-covered", packs: [], degraded: `${noLabel}, and no generic ${languages.join("/")} request shape either` };
  }
  const why: string[] = [];
  for (const o of owners) {
    if (!o.version) continue;
    const off = [...new Set(mine.filter((i) => i.framework === o.id && !satisfies(o.version!, i.testedWith)).map((i) => `${i.title} (${i.testedWith})`))];
    if (off.length) why.push(`${o.title} ${o.version} is outside the catalog's testedWith for ${off.join(", ")}`);
  }
  return { ...base, state: "deterministic", packs: ["catalog"], ...(why.length ? { degraded: why.join("; ") } : {}) };
}

/** The static matrix for the detected stack — what the scan itself can say. */
export function classCoverage(
  stack: readonly DetectedFramework[],
  packs: readonly Pack[] = PACKS,
  idioms: readonly CatalogIdiom[] = catalogIdioms(),
): ClassCoverageCell[] {
  const cells: ClassCoverageCell[] = [];
  const libraries = stack.filter((f) => f.kind === "library");
  for (const f of stack) {
    if (f.kind === "library") continue;
    const languages = languagesOf(f);
    const fwPack = f.kind === "inferred" ? undefined : packs.find((p) => p.framework === f.id);
    // The libraries declared in this framework's package, with a pack of their own.
    const libs = attachedLibraries(f, libraries);
    const libPacks = libs.flatMap((l) => packs.filter((p) => p.library === l.id).map((p) => ({ lib: l, pack: p })));
    // Language idioms: the packs tied to no framework or library whose rules
    // read a language this framework's code is written in.
    const langPacks = packs.filter((p) => !p.framework && !p.library && readsAny(p, languages));
    const columnOutOfRange = fwPack ? outside(f, fwPack) : undefined;
    const noPack = f.kind === "inferred" ? `${f.title} — no pack can know it` : `no ${f.title} pack`;

    for (const c of CLASS_LIST) {
      const base = { class: c.id, framework: f.id, ecosystem: f.ecosystem, dir: f.dir, ...(f.version ? { version: f.version } : {}) };
      const considered = [...(fwPack ? [fwPack] : []), ...libPacks.map((x) => x.pack), ...langPacks];
      const ruled = considered.filter((p) => rulesFor(p, c.id, languages));
      const declared = considered.map((p) => p.classes[c.id]).filter((cov) => cov && !("rules" in cov));
      const na = declared.find((cov) => cov && "notApplicable" in cov);
      if (!ruled.length && na && "notApplicable" in na) {
        cells.push({ ...base, state: "not-applicable", packs: [], reason: na.notApplicable });
        continue;
      }
      const why: string[] = [];
      // A framework pack that says "hunt this" outranks the language floor: the
      // floor still ran, but the framework's own idiom is not encoded.
      const fwWord = fwPack?.classes[c.id];
      if (ruled.length && fwWord && "hunt" in fwWord) why.push(fwWord.hunt);
      if (columnOutOfRange) why.push(columnOutOfRange);
      for (const { lib, pack } of libPacks) {
        const off = ruled.includes(pack) ? outside(lib, pack) : undefined;
        if (off) why.push(off);
      }
      if (!ruled.length) {
        const hunt = declared.find((cov) => cov && "hunt" in cov);
        const reason = hunt && "hunt" in hunt ? hunt.hunt : fwPack ? `pack ${fwPack.id} has no idiom for this class` : noPack;
        cells.push({ ...base, state: "not-covered", packs: [], degraded: [reason, ...why].join("; ") });
        continue;
      }
      if (!fwPack)
        why.unshift(
          `${noPack} — only the ${[...new Set(ruled.map((p) => (p.ecosystem === "*" ? "language-agnostic" : p.ecosystem)))].join("/")} language idioms ran`,
        );
      cells.push({ ...base, state: "deterministic", packs: ruled.map((p) => p.id), ...(why.length ? { degraded: why.join("; ") } : {}) });
    }
    cells.push(catalogCell(f, libs, idioms));
  }
  return cells;
}

/**
 * What the matrix (and the manifest's `frameworks`) is built from: the known
 * web frameworks, the inferred ones, and the libraries some pack is written
 * against — a library nothing is written against changes no cell.
 */
export function matrixStack(
  stack: readonly DetectedFramework[],
  inferred: readonly DetectedFramework[] = [],
  packs: readonly Pack[] = PACKS,
): DetectedFramework[] {
  const libraryIds = new Set([...packs.flatMap((p) => (p.library ? [p.library] : [])), ...catalogIdioms().map((i) => i.framework)]);
  return [...stack.filter((f) => f.kind !== "library"), ...inferred, ...stack.filter((f) => f.kind === "library" && libraryIds.has(f.id))];
}

/** The hunt ids a run's investigate worklist emitted, and the ones its apply recorded as hunted. */
export function huntProgress(run: string): { emitted: Set<string>; hunted: Set<string> } {
  const emitted = new Set<string>();
  const hunted = new Set<string>();
  try {
    const todo = join(run, "INVESTIGATE.todo.json");
    if (existsSync(todo)) for (const r of readInvestigateTodo(JSON.parse(readFileSync(todo, "utf8")))) if (r.hunt?.id) emitted.add(r.hunt.id);
  } catch {
    /* an unreadable worklist hunts nothing */
  }
  try {
    const sug = readPath(run, PACK_SUGGESTIONS_FILE);
    if (existsSync(sug)) for (const id of (JSON.parse(readFileSync(sug, "utf8")) as { hunted?: string[] }).hunted ?? []) hunted.add(id);
  } catch {
    /* an unreadable suggestions file records nothing */
  }
  return { emitted, hunted };
}

/** The matrix as the run stands: the scan's cells, moved to `ai-hunt` once the
 *  worklist emitted their hunt and to `ai-hunted` once an apply recorded it. */
export function withHuntProgress(cells: readonly ClassCoverageCell[], run?: string): ClassCoverageCell[] {
  if (!run) return [...cells];
  const { emitted, hunted } = huntProgress(run);
  return cells.map((c) => {
    if (!needsHunt(c)) return c;
    const id = huntId(c);
    if (hunted.has(id)) return { ...c, state: "ai-hunted" };
    if (emitted.has(id)) return { ...c, state: "ai-hunt" };
    return c;
  });
}

const MARK: Record<ClassCellState, string> = {
  deterministic: "✅ pack",
  "not-applicable": "➖ n/a",
  "not-covered": "⬜ **not covered**",
  "ai-hunt": "🔎 AI hunt pending",
  "ai-hunted": "🧭 AI hunted",
};

/** The class × framework matrix as Markdown, for COVERAGE.md and REPORT.md (no trailing newline). */
export function renderClassCoverageMd(cells: readonly ClassCoverageCell[]): string {
  if (!cells.length) return "";
  const columns = [...new Map(cells.map((c) => [`${c.framework}@${c.dir}`, c])).values()];
  const L: string[] = ["### Weakness classes × frameworks", ""];
  L.push("Each detected framework against each weakness class: matched by a pack (`✅`), not applicable (`➖`),");
  L.push("handed to the AI hunt (`🔎` pending, `🧭` done), or **not covered**. A `⚠` cell is degraded — no framework");
  L.push("pack, or a version outside the range the pack was validated on — and is hunted, not trusted.");
  L.push("");
  L.push(`| class | ${columns.map((c) => `${c.framework}${c.version ? ` ${c.version}` : ""}${c.dir ? ` (\`${c.dir}\`)` : ""}`).join(" | ")} |`);
  L.push(`|---|${columns.map(() => "---").join("|")}|`);
  for (const cls of MATRIX_ROWS) {
    const row = columns.map((col) => {
      const cell = cells.find((c) => c.class === cls.id && c.framework === col.framework && c.dir === col.dir);
      return cell ? `${MARK[cell.state]}${cell.degraded ? " ⚠" : ""}` : "—";
    });
    L.push(`| ${cls.id} | ${row.join(" | ")} |`);
  }
  L.push("");
  const degraded = cells.filter((c) => c.degraded);
  if (degraded.length) {
    L.push(
      `Degraded or uncovered (${degraded.length}): ${[...new Set(degraded.map((c) => `${c.framework}${c.dir ? ` (${c.dir})` : ""} — ${c.degraded}`))].join("; ")}.`,
    );
    L.push("Run `ultrasec investigate` — it emits one hunt per such cell.");
  }
  return L.join("\n").replace(/\n+$/, "");
}
