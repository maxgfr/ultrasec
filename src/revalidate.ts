import type { Dossier } from "./store.js";
import type { Finding, Status } from "./types.js";
import { isHigh } from "./verify.js";
import { byStr } from "./util.js";
import { fileExistsAtHead, lineContentAtHead, lineLastChanged, fileRenamedTo, logSince, type LineChange } from "./git.js";

// The git-history revalidation stage (Phase 2 — the biggest accuracy win, mirrors
// deepsec's "revalidate" pass that cuts false positives 50%+). For each finding
// the engine ALREADY ranked real (status confirmed/needs-human), it emits compact
// git facts about the cited location — does the file/line still exist? what's
// there now? when did it last change? — and the agent decides whether the issue is
// still-valid / fixed / false-positive / uncertain. Apply is CONSERVATIVE: `fixed`
// dismisses with a fixed-in commit; a high-severity `false-positive` is escalated
// to needs-human (never silently dropped); anything uncertain → needs-human.

export const REVALIDATION_VERDICTS = ["still-valid", "fixed", "false-positive", "uncertain"] as const;
export type RevalidationVerdict = (typeof REVALIDATION_VERDICTS)[number];

/** Findings this stage revalidates: the ones the pipeline already promoted. */
function inScope(f: Finding): boolean {
  return f.status === "confirmed" || f.status === "needs-human";
}

/** The primary cited location of a finding (sink → last path step → source). */
export function citedLoc(f: Finding): { file: string; line: number } | null {
  if (f.sink) return { file: f.sink.file, line: f.sink.line };
  const last = f.path?.[f.path.length - 1];
  if (last) return { file: last.file, line: last.line };
  if (f.source) return { file: f.source.file, line: f.source.line };
  return null;
}

export interface RevalidateItem {
  id: string;
  severity: string;
  title: string;
  /** Cited "file:line" the facts below describe. */
  at: string;
  /** Does the cited file still exist at HEAD? */
  fileExists: boolean;
  /** The current content of the cited line at HEAD (null if file/line is gone). */
  currentLine: string | null;
  /** Commits to the file since the finding's provenance commit (null if unknown). */
  commitsSinceFinding: number | null;
  /** The commit that last changed the cited line (null if unavailable/huge file). */
  lineLastChanged: LineChange | null;
  /** If the file was deleted, the path it was likely renamed to (best-effort). */
  renamedTo: string | null;
  /** Filled by the agent. */
  verdict: RevalidationVerdict | null;
  /** Optional: the fixing commit (else inferred from lineLastChanged on apply). */
  fixedIn?: string;
  note: string;
}

export interface RevalidationInput {
  id: string;
  verdict: RevalidationVerdict;
  fixedIn?: string;
  note?: string;
}

/** Build the revalidation worklist from a run's confirmed/needs-human findings. */
export function buildRevalidateWorklist(dossier: Dossier, repo: string): RevalidateItem[] {
  return dossier.findings
    .filter(inScope)
    .slice()
    .sort((a, b) => byStr(a.id, b.id))
    .map((f) => {
      const loc = citedLoc(f);
      const file = loc?.file ?? "";
      const line = loc?.line ?? 0;
      const fileExists = file ? fileExistsAtHead(repo, file) : false;
      const currentLine = fileExists && line ? lineContentAtHead(repo, file, line) : null;
      const sinceRef = f.provenance?.commit;
      const since = sinceRef && file ? logSince(repo, file, sinceRef) : null;
      return {
        id: f.id,
        severity: f.severity,
        title: f.title,
        at: `${file}:${line}`,
        fileExists,
        currentLine,
        commitsSinceFinding: since ? since.length : null,
        lineLastChanged: fileExists && line ? lineLastChanged(repo, file, line) : null,
        renamedTo: file && !fileExists ? fileRenamedTo(repo, file) : null,
        verdict: null,
        note: "",
      };
    });
}

export function renderRevalidateMd(items: RevalidateItem[], context?: string): string {
  const L: string[] = [];
  L.push(`# ultrasec revalidation worklist (${items.length})`);
  L.push("");
  L.push(`Each finding below was already ranked **real** (confirmed / needs-human). Using the`);
  L.push(`git facts, decide whether it is still a live issue and set a \`verdict\`:`);
  L.push(`\`still-valid\` · \`fixed\` · \`false-positive\` · \`uncertain\` (+ a short \`note\`, and`);
  L.push(`\`fixedIn\` — the fixing commit sha — when \`fixed\`). Save as REVALIDATE.json (array of`);
  L.push(`{id, verdict, fixedIn?, note?}) and run \`ultrasec revalidate --apply REVALIDATE.json\`.`);
  L.push("");
  L.push(`> Conservative on apply: \`fixed\` → dismissed (records the fixing commit);`);
  L.push(`> a high/critical \`false-positive\` → **needs-human** (never auto-dismissed);`);
  L.push(`> \`uncertain\`/unknown → needs-human. \`still-valid\` keeps the finding as-is.`);
  L.push("");
  if (context) {
    L.push(`## Project context`);
    L.push(`_From \`CONTEXT.md\` — the project's trust model; background, never a verdict._`);
    L.push("");
    L.push(context);
    L.push("");
  }
  for (const it of items) {
    L.push(`## ${it.id} — [${it.severity}] ${it.title}`);
    L.push(`- at: \`${it.at}\` · file exists at HEAD: ${it.fileExists ? "yes" : "**NO**"}`);
    if (it.currentLine !== null) L.push(`- current line: \`${it.currentLine.trim().slice(0, 200)}\``);
    else if (it.fileExists) L.push(`- current line: **cited line is out of range now (drifted/removed)**`);
    if (it.commitsSinceFinding !== null) L.push(`- commits to file since finding: ${it.commitsSinceFinding}`);
    if (it.lineLastChanged)
      L.push(
        `- line last changed: \`${it.lineLastChanged.commit}\`${it.lineLastChanged.date ? ` (${it.lineLastChanged.date})` : ""}${it.lineLastChanged.author ? ` by ${it.lineLastChanged.author}` : ""}`,
      );
    if (it.renamedTo) L.push(`- file appears renamed to: \`${it.renamedTo}\``);
    L.push("");
  }
  return L.join("\n") + "\n";
}

export interface ApplyRevalResult {
  findings: Finding[];
  applied: number;
  stillValid: number;
  fixed: number;
  dismissed: number;
  needsHuman: number;
  /** Drift guards + escalations the human should re-check. */
  flagged: { id: string; reason: string }[];
  /** Stale verdicts: ids not in the revalidation scope (unknown, or no longer
   *  confirmed/needs-human), sorted — reported, never silently dropped. */
  ignored: string[];
}

export interface ApplyRevalOptions {
  /** Finding ids whose cited location no longer resolves at HEAD (drift guard). */
  unresolved?: Set<string>;
  /** Inferred fixing commit per id (lineLastChanged), used when the agent omits fixedIn. */
  fixedInById?: Map<string, string>;
}

/**
 * Fold revalidation verdicts back in under the conservative policy. Only acts on
 * in-scope findings (confirmed / needs-human); never touches path/source/sink/
 * title/severity. A `still-valid` verdict on a finding whose cited location no
 * longer resolves is KEPT but flagged for re-confirmation.
 */
export function applyRevalidations(dossier: Dossier, inputs: RevalidationInput[], opts: ApplyRevalOptions = {}): ApplyRevalResult {
  const byId = new Map<string, RevalidationInput>();
  for (const v of inputs) byId.set(v.id, v); // last-wins on dupes
  const inScopeIds = new Set(dossier.findings.filter(inScope).map((f) => f.id));
  const ignored = [...byId.keys()].filter((id) => !inScopeIds.has(id)).sort(byStr);
  const unresolved = opts.unresolved ?? new Set<string>();
  const fixedInById = opts.fixedInById ?? new Map<string, string>();

  let applied = 0,
    stillValid = 0,
    fixed = 0,
    dismissed = 0,
    needsHuman = 0;
  const flagged: ApplyRevalResult["flagged"] = [];

  const withNote = (f: Finding, label: string, note?: string): string => `${f.message}\n\nRevalidation (${label})${note ? `: ${note}` : ""}`;

  const findings = dossier.findings.map((f) => {
    const v = byId.get(f.id);
    if (!v || !inScope(f)) return f; // out of scope / no verdict → untouched
    applied++;

    switch (v.verdict) {
      case "still-valid": {
        stillValid++;
        let message = f.message;
        if (unresolved.has(f.id)) {
          flagged.push({ id: f.id, reason: "marked still-valid but cited location no longer resolves at HEAD — re-confirm" });
          message = withNote(f, "still-valid", `${v.note ? v.note + " " : ""}⚠️ cited location drifted/removed at HEAD — re-confirm the line`);
        } else if (v.note) {
          message = withNote(f, "still-valid", v.note);
        }
        return { ...f, message };
      }
      case "fixed": {
        fixed++;
        dismissed++;
        const sha = v.fixedIn ?? fixedInById.get(f.id);
        const next: Finding = {
          ...f,
          status: "dismissed" as Status,
          message: withNote(f, "fixed", `${v.note ? v.note + " " : ""}${sha ? `fixed in ${sha}` : "fixed"}`),
        };
        if (sha) next.fixedIn = sha;
        return next;
      }
      case "false-positive": {
        const status: Status = isHigh(f.severity) ? "needs-human" : "dismissed";
        if (status === "needs-human") {
          needsHuman++;
          flagged.push({ id: f.id, reason: "high-severity false-positive — escalated to needs-human, not auto-dismissed" });
        } else {
          dismissed++;
        }
        return { ...f, status, message: withNote(f, "false-positive", v.note) };
      }
      default: {
        // "uncertain" / unknown → never silently drop.
        needsHuman++;
        return { ...f, status: "needs-human" as Status, message: withNote(f, v.verdict, v.note) };
      }
    }
  });

  return { findings, applied, stillValid, fixed, dismissed, needsHuman, flagged, ignored };
}

/**
 * Parse a REVALIDATE.json body: a JSON array, {revalidations:[...]}, or
 * {verdicts:[...]} — the shape the orchestrate-emitted REVALIDATE_SCHEMA and
 * revalidator contract return. FAIL-CLOSED: an unrecognized container shape, or
 * rows that all get dropped, throws instead of yielding 0 rows — otherwise the
 * false-positive cut silently never happens ("applied 0", exit 0).
 */
export function parseRevalidations(raw: string): RevalidationInput[] {
  const data = JSON.parse(raw) as unknown;
  const arr = Array.isArray(data)
    ? data
    : Array.isArray((data as any)?.revalidations)
      ? (data as any).revalidations
      : Array.isArray((data as any)?.verdicts)
        ? (data as any).verdicts
        : null;
  if (arr === null) throw new Error(`unrecognized revalidations shape — expected a JSON array, {"verdicts":[...]} or {"revalidations":[...]} (fail-closed)`);
  const out = (arr as any[])
    .filter((v) => v && typeof v.id === "string" && (REVALIDATION_VERDICTS as readonly string[]).includes(v.verdict))
    .map((v) => ({
      id: v.id as string,
      verdict: v.verdict as RevalidationVerdict,
      fixedIn: typeof v.fixedIn === "string" ? v.fixedIn : undefined,
      note: typeof v.note === "string" ? v.note : undefined,
    }));
  if (arr.length > 0 && out.length === 0) {
    throw new Error(`${arr.length} row(s), none usable — each needs a string "id" and a "verdict" among ${REVALIDATION_VERDICTS.join("|")} (fail-closed)`);
  }
  return out;
}

/** Derive the apply-time git-fact helpers (drift set + inferred fixing commits)
 *  from a freshly-built worklist, so apply reflects the repo's CURRENT state. */
export function revalFactsFromWorklist(items: RevalidateItem[]): ApplyRevalOptions {
  const unresolved = new Set<string>();
  const fixedInById = new Map<string, string>();
  for (const it of items) {
    if (!it.fileExists || it.currentLine === null) unresolved.add(it.id);
    if (it.lineLastChanged?.commit) fixedInById.set(it.id, it.lineLastChanged.commit);
  }
  return { unresolved, fixedInById };
}
