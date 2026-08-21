import type { Finding } from "./types.js";
import { compareWithinStatus } from "./rank.js";
import { byStr, stageNotes } from "./util.js";

// Collapsing a repeated finding into ONE entry with a count.
//
// A large audit is not a list of N distinct problems. On the run that motivated
// this, 1366 findings contained four repeated bandit titles accounting for 604
// of them, and the top two titles alone were 279 rows. Every consumer paid for
// that separately: the triage worklist asked for 1342 one-line decisions, the
// Markdown report emitted a full section with a mermaid diagram per row, and the
// HTML grew to 2.1 MB — a report nobody can read is not a report.
//
// The grouping is by (title × path root × ADJUDICATION), because that is the
// unit a reader actually decides about: "149 pickle warnings under analysis/,
// all refuted for the same reason" is one judgment, and splitting it into 149
// identical ones does not make the audit more thorough, only longer.
//
// The adjudication belongs in the key, and leaving it out was a real defect.
// Keyed on (title × root) alone, 38 of 69 families on a real audit contained
// DIFFERENT refutation arguments — 384 distinct ones across the run — and
// collapsing them onto one exemplar presented several judgments as one. Adding
// it splits those into honest groups: on that same run, 78 families instead of
// 69, still folding 503 rows away. Slightly less compression, and it is no
// longer bought by conflating things a reader has to be able to disagree with
// separately.
//
// ── Grouping is for READING, never for deciding ────────────────────────────
//
// This is the same rule `noise.ts` states for its proposal summary, and it
// matters more here. A family shows one member in full and lists the rest; it
// never merges them into a single finding, never rewrites an id, and never lets
// one verdict travel to members an apply file did not name. `findings.json`
// still holds every finding individually — the fold is presentation, and the
// audit trail is untouched.

/** Members needed before a repetition is worth collapsing. Two of a thing read
 *  fine in full; the fold starts paying off at three. */
const MIN_FAMILY = 3;

/**
 * The part of a path a family is keyed on: up to the first two directory
 * segments.
 *
 * One segment collapses a monorepo — `targets/frontend` and `targets/ingester`
 * are different components with different exposure, and merging them would hide
 * exactly the distinction an auditor is grouping in order to see. Two segments
 * separate them while still gathering a whole `.venv` or `node_modules` tree,
 * which is the case worth gathering.
 */
export function pathRoot(file: string): string {
  const parts = file.split("/");
  if (parts.length <= 1) return ".";
  return parts.slice(0, Math.min(2, parts.length - 1)).join("/");
}

function locationOf(f: Finding): string | undefined {
  return f.sink?.file ?? f.source?.file ?? f.path?.[f.path.length - 1]?.file;
}

/** Joins the two halves of a family key. A literal that cannot occur in a title
 *  or a path, so `("ab", "cd/e")` and `("abc", "d/e")` cannot collide. */
const KEY_SEP = " :: ";

/** Prefix for a finding that has no location and so belongs to no path family. */
const UNPLACED = "unplaced" + KEY_SEP;

export interface Family {
  /** Stable key — title, path root, adjudication. Never displayed. */
  key: string;
  title: string;
  root: string;
  /** The adjudication every member shares — the reason they are ONE judgment.
   *  Empty when the family is unadjudicated (an `open` tier). */
  note: string;
  /** The best-ranked member, rendered in full as the family's exemplar. */
  lead: Finding;
  /** Every member, `lead` included, in rank order. */
  members: Finding[];
}

export interface Grouped {
  /** Repetitions worth collapsing, best-ranked family first. */
  families: Family[];
  /** Everything that repeats fewer than `MIN_FAMILY` times, in rank order. */
  singles: Finding[];
}

/**
 * Split findings into collapsible families and the rest.
 *
 * Order is preserved from `compareWithinStatus`, so a family sits where its best
 * member would have sat and a collapsed group never jumps the queue. Callers
 * that have not already split by status should do so first — a family spanning
 * `confirmed` and `dismissed` would be one entry with two different meanings.
 */
export function groupFamilies(findings: readonly Finding[], minFamily = MIN_FAMILY): Grouped {
  const byKey = new Map<string, Finding[]>();
  for (const f of findings) {
    const at = locationOf(f);
    // A finding with no location cannot be placed in a path family, and its
    // title alone is too weak a key — dependency advisories all cite the same
    // lockfile line but are genuinely distinct CVEs.
    const key = at ? f.title + KEY_SEP + pathRoot(at) + KEY_SEP + stageNotes(f.message) : UNPLACED + f.id;
    const list = byKey.get(key);
    if (list) list.push(f);
    else byKey.set(key, [f]);
  }

  const families: Family[] = [];
  const singles: Finding[] = [];
  for (const [key, members] of byKey) {
    if (members.length < minFamily) {
      singles.push(...members);
      continue;
    }
    const ranked = members.slice().sort(compareWithinStatus);
    const lead = ranked[0]!;
    families.push({ key, title: lead.title, root: pathRoot(locationOf(lead)!), note: stageNotes(lead.message), lead, members: ranked });
  }

  families.sort((a, b) => compareWithinStatus(a.lead, b.lead) || byStr(a.key, b.key));
  singles.sort(compareWithinStatus);
  return { families, singles };
}

/** "×149" — what a family's collapse actually saved the reader. */
export function familyCount(f: Family): string {
  return `×${f.members.length}`;
}

/** How many findings the fold removed from the page (members beyond each lead). */
export function collapsedCount(grouped: Grouped): number {
  return grouped.families.reduce((n, f) => n + f.members.length - 1, 0);
}
