import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { flagBool, flagStr, println, eprintln, type ParsedArgs } from "../util.js";
import { loadDossier } from "../store.js";
import { renderSummary, renderReport } from "../render/report.js";
import { renderHtml } from "../render/html.js";
import { parseNarrative, mergeNarrative, hasNarrativeContent } from "../narrative.js";
import { unadjudicatedCode } from "../surface.js";
import type { Narrative } from "../types.js";

// `ultrasec render --run <dir> [--narrative <file>] [--draft]` → SUMMARY/REPORT.md + index.html
// With --narrative, the agent-authored Narrative is folded in as additive,
// clearly-marked AI sections (grounding-checked: sections citing unknown/non-
// confirmed ids are dropped). Without --narrative the output is byte-identical.
//
// ── Why render can fail ────────────────────────────────────────────────────
//
// One audit ran `scan` → `guards` → `render` and shipped 882 candidates, none
// adjudicated, every `why` cell a dash. `check --semantic` would have caught
// it, but nothing makes `render` depend on `check`, so the gate that exists was
// simply never reached — and the document that came out looked like a report.
//
// So render carries the check itself, for the one class where "open" is not a
// legitimate resting place: HIGH/CRITICAL candidates in the repo's own code.
// Dependency advisories may stay open — triaging the ranked list and stopping
// at the bar is what references/supply-chain.md prescribes.
//
// The files are ALWAYS written. Refusing to produce them would trade a
// misleading report for no report, and the banner inside them is the part that
// actually travels: an exit code is gone the moment the terminal scrolls, and
// the HTML is what gets shared. `--draft` acknowledges the state and exits 0.
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
    ["index.html", renderHtml(dossier, narrative)],
  ];
  for (const [name, body] of outputs) writeFileSync(join(run, name), body);

  println(`ultrasec render → ${run}`);
  for (const [name] of outputs) println(`  ${join(run, name)}`);
  if (narrativeNote) println(narrativeNote);

  const unread = unadjudicatedCode(dossier.findings);
  if (!unread.length) return 0;

  const draft = flagBool(args, "draft");
  const crit = unread.filter((f) => f.severity === "critical").length;
  println(`  ⚠️  ${unread.length} source-code candidate(s) at HIGH+ were never read (${crit} critical) — the report says so in a banner.`);
  println(
    `      next: ultrasec paths --run ${run} --surface code  →  ultrasec dossier <id> --run ${run}  →  ultrasec verify --apply verdicts.json --run ${run}`,
  );
  if (draft) {
    println(`      --draft: exiting 0 on an acknowledged incomplete audit.`);
    return 0;
  }
  println(`      exit 1 — rendered anyway; pass --draft when an incomplete audit is what you meant.`);
  return 1;
}
