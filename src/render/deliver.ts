import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Dossier } from "../store.js";
import type { Narrative } from "../types.js";
import { loadLedger } from "../council/ledger.js";
import { hasNarrativeContent, mergeNarrative, parseNarrative } from "../narrative.js";
import { renderAuditReport, reportStatus, type AuditReportOptions, type ReportStatus } from "./audit-report.js";
import { renderReportHtml } from "./md-html.js";
import { renderReport, renderSummary } from "./report.js";
import { renderHtml } from "./html.js";
import { KEPT_FILES } from "../runlayout.js";

// Writing THE report — the one function `render`, `run` and `audit` share, so
// the three can never produce different deliverables for the same run.
//
// One file by default: `REPORT.md`, or `REPORT.html` with `html` (both only
// when both are asked for). The previous trio — SUMMARY.md, the tiered
// REPORT.md and index.html — is the `legacy` escape hatch, kept for consumers
// that parse it; it is never written unless asked for.

export interface DeliverOptions {
  /** Write REPORT.html. */
  html?: boolean;
  /** Write REPORT.md — implied when `html` is off. */
  md?: boolean;
  /** Exhaustive annexes (see `AuditReportOptions.full`). */
  full?: boolean;
  /** The previous layout instead: SUMMARY.md + tiered REPORT.md + index.html. */
  legacy?: boolean;
  narrative?: Narrative;
  grounding?: AuditReportOptions["grounding"];
}

export interface Delivered {
  written: string[];
  /** Stale outputs of another format/layout removed so one report remains. */
  removed: string[];
  status: ReportStatus;
}

/**
 * The narrative to fold in: the run's own `NARRATIVE.json` when the caller
 * names none. Grounding-checked through `mergeNarrative` either way, so a
 * stale narrative citing ids that are no longer confirmed loses those sections
 * instead of decorating the wrong findings.
 */
export function runNarrative(run: string, dossier: Dossier, explicit?: string): { narrative?: Narrative; error?: string } {
  const at = explicit ?? join(run, "NARRATIVE.json");
  if (!existsSync(at)) return explicit ? { error: `cannot read narrative at ${explicit}: no such file` } : {};
  try {
    const merged = mergeNarrative(parseNarrative(readFileSync(at, "utf8")), dossier);
    return hasNarrativeContent(merged) ? { narrative: merged } : {};
  } catch (e) {
    return { error: `cannot read narrative at ${at}: ${(e as Error).message}` };
  }
}

export function deliverReport(run: string, dossier: Dossier, opts: DeliverOptions = {}): Delivered {
  const status = reportStatus(dossier, opts.grounding);
  const written: string[] = [];
  const removed: string[] = [];
  const write = (name: string, body: string): void => {
    writeFileSync(join(run, name), body);
    written.push(join(run, name));
  };

  if (opts.legacy) {
    write("SUMMARY.md", renderSummary(dossier, opts.narrative));
    write("REPORT.md", renderReport(dossier, opts.narrative));
    write("index.html", renderHtml(dossier, opts.narrative));
    return { written, removed, status };
  }

  const wantHtml = !!opts.html;
  const wantMd = !!opts.md || !wantHtml;
  let council: AuditReportOptions["council"];
  try {
    council = loadLedger(run);
  } catch {
    /* an unreadable ledger is reported by `council`, not by the report */
  }
  const names = [...(wantMd ? ["REPORT.md"] : []), ...(wantHtml ? ["REPORT.html"] : [])];
  const artifacts = KEPT_FILES.filter((f) => names.includes(f) || (!f.startsWith("REPORT.") && existsSync(join(run, f))));
  const md = renderAuditReport(dossier, { narrative: opts.narrative, council, full: opts.full, grounding: opts.grounding, artifacts });
  if (wantMd) write("REPORT.md", md);
  if (wantHtml) write("REPORT.html", renderReportHtml(md));

  // One report per run: a format not written this time, or the previous
  // layout's outputs, would sit next to the new report and contradict it.
  for (const stale of [...(wantMd ? [] : ["REPORT.md"]), ...(wantHtml ? [] : ["REPORT.html"]), "SUMMARY.md", "index.html"]) {
    const p = join(run, stale);
    if (existsSync(p)) {
      rmSync(p, { force: true });
      removed.push(p);
    }
  }
  return { written, removed, status };
}
