import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { flagStr, println, eprintln, type ParsedArgs } from "../util.js";
import { loadDossier } from "../store.js";
import { renderSummary, renderReport, renderFull } from "../render/report.js";
import { renderHtml } from "../render/html.js";
import { parseNarrative, mergeNarrative, hasNarrativeContent } from "../narrative.js";
import type { Narrative } from "../types.js";

// `ultrasec render --run <dir> [--narrative <file>]` → SUMMARY/REPORT/FULL.md + index.html
// With --narrative, the agent-authored Narrative is folded in as additive,
// clearly-marked AI sections (grounding-checked: sections citing unknown/non-
// confirmed ids are dropped). Without --narrative the output is byte-identical.
export function runRender(args: ParsedArgs): number {
  const run = resolve(flagStr(args, "run") ?? ".ultrasec");
  let dossier: ReturnType<typeof loadDossier>;
  try {
    dossier = loadDossier(run);
  } catch (e) {
    eprintln(`ultrasec render: ${(e as Error).message}`);
    return 2;
  }

  let narrative: Narrative | undefined;
  let narrativeNote = "";
  const narrativePath = flagStr(args, "narrative");
  if (narrativePath) {
    let parsed: Narrative;
    try {
      parsed = parseNarrative(readFileSync(resolve(narrativePath), "utf8"));
    } catch (e) {
      eprintln(`ultrasec render: cannot read narrative at ${narrativePath}: ${(e as Error).message}`);
      return 2;
    }
    const merged = mergeNarrative(parsed, dossier);
    narrative = merged;
    narrativeNote = hasNarrativeContent(merged)
      ? `  + AI narrative folded in (${merged.remediations?.length ?? 0} fix(es), ${merged.attackChains?.length ?? 0} chain(s), ${merged.rootCauses?.length ?? 0} root-cause group(s)${merged.executiveSummary ? ", exec summary" : ""}${merged.positivePatterns ? ", positive patterns" : ""}${merged.hardeningNotes?.length ? `, ${merged.hardeningNotes.length} hardening note(s)` : ""})`
      : `  ⚠️  narrative had no sections grounded on confirmed findings — report rendered without it`;
  }

  const outputs: [string, string][] = [
    ["SUMMARY.md", renderSummary(dossier, narrative)],
    ["REPORT.md", renderReport(dossier, narrative)],
    ["FULL.md", renderFull(dossier, narrative)],
    ["index.html", renderHtml(dossier, narrative)],
  ];
  for (const [name, body] of outputs) writeFileSync(join(run, name), body);

  println(`ultrasec render → ${run}`);
  for (const [name] of outputs) println(`  ${join(run, name)}`);
  if (narrativeNote) println(narrativeNote);
  return 0;
}
