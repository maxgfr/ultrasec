import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { DetectedFramework } from "../frameworks.js";
import { satisfies } from "../frameworks.js";
import { CLASS_LIST } from "./registry.js";
import { PACKS } from "./packs/index.js";
import type { ClassId, Pack } from "./types.js";

// The weakness-class × framework matrix — which detected framework each class
// was matched for by a pack, which it was hunted for by the AI, and which
// nobody looked at.
//
// A pack is only a claim inside the version range it was validated against.
// So a cell is DEGRADED when the framework has no pack at all (only language
// idioms applied) or its version is outside the pack's `testedWith`: the rules
// still ran — a floor is better than nothing — but the cell says so, and the
// `investigate` worklist hunts it.

export const CLASS_CELL_STATES = ["deterministic", "not-applicable", "not-covered", "ai-hunt", "ai-hunted"] as const;
export type ClassCellState = (typeof CLASS_CELL_STATES)[number];

export interface ClassCoverageCell {
  class: ClassId;
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

/** The static matrix for the detected frameworks — what the scan itself can say. */
export function classCoverage(frameworks: readonly DetectedFramework[], packs: readonly Pack[] = PACKS): ClassCoverageCell[] {
  const cells: ClassCoverageCell[] = [];
  for (const f of frameworks) {
    const fwPack = packs.find((p) => p.framework === f.id);
    const ecoPacks = packs.filter((p) => !p.framework && (p.ecosystem === f.ecosystem || p.ecosystem === "*"));
    const outOfRange = fwPack?.testedWith && f.version && !satisfies(f.version, fwPack.testedWith) ? fwPack.testedWith : undefined;
    for (const c of CLASS_LIST) {
      const base = { class: c.id, framework: f.id, ecosystem: f.ecosystem, dir: f.dir, ...(f.version ? { version: f.version } : {}) };
      const considered = [...(fwPack ? [fwPack] : []), ...ecoPacks];
      const ruled = considered.filter((p) => {
        const cov = p.classes[c.id];
        return cov && "rules" in cov && cov.rules.length > 0;
      });
      const na = considered.map((p) => p.classes[c.id]).find((cov) => cov && "notApplicable" in cov);
      if (!ruled.length && na && "notApplicable" in na) {
        cells.push({ ...base, state: "not-applicable", packs: [], reason: na.notApplicable });
        continue;
      }
      if (!ruled.length) {
        cells.push({ ...base, state: "not-covered", packs: [], degraded: fwPack ? `pack ${fwPack.id} has no idiom for this class` : `no ${f.title} pack` });
        continue;
      }
      const degraded = !fwPack
        ? `no ${f.title} pack — only the ${f.ecosystem} language idioms ran`
        : outOfRange && ruled.includes(fwPack)
          ? `${f.title} ${f.version} is outside ${fwPack.id} testedWith ${outOfRange}`
          : undefined;
      cells.push({ ...base, state: "deterministic", packs: ruled.map((p) => p.id), ...(degraded ? { degraded } : {}) });
    }
  }
  return cells;
}

/** The hunt ids a run's investigate worklist emitted, and the ones its apply recorded as hunted. */
export function huntProgress(run: string): { emitted: Set<string>; hunted: Set<string> } {
  const emitted = new Set<string>();
  const hunted = new Set<string>();
  try {
    const todo = join(run, "INVESTIGATE.todo.json");
    if (existsSync(todo)) for (const r of JSON.parse(readFileSync(todo, "utf8")) as { hunt?: { id?: string } }[]) if (r.hunt?.id) emitted.add(r.hunt.id);
  } catch {
    /* an unreadable worklist hunts nothing */
  }
  try {
    const sug = join(run, PACK_SUGGESTIONS_FILE);
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
  for (const cls of CLASS_LIST) {
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
