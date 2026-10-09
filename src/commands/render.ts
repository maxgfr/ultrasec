import { existsSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { flagBool, flagStr, println, eprintln, type ParsedArgs } from "../util.js";
import { loadDossier, type Dossier } from "../store.js";
import { check } from "../check.js";
import { unadjudicatedCode } from "../surface.js";
import { deliverReport, runNarrative } from "../render/deliver.js";
import { statusLine } from "../render/audit-report.js";
import type { Narrative } from "../types.js";

// `ultrasec render --run <dir> [--html] [--md] [--full] [--narrative <file>] [--strict] [--draft] [--legacy]`
//   → <run>/REPORT.md (or REPORT.html) — ONE file with the whole audit.
//
// The narrative is the run's own NARRATIVE.json unless `--narrative` names
// another; it is grounding-checked either way (sections citing ids that are not
// confirmed are dropped). `--legacy` writes the previous SUMMARY.md + tiered
// REPORT.md + index.html instead, for consumers that parse them.
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
// The file is ALWAYS written. Refusing to produce it would trade a misleading
// report for no report, and the DRAFT banner inside it is the part that
// actually travels: an exit code is gone the moment the terminal scrolls, and
// the report is what gets shared. So a written report exits 0, like `audit`;
// `--strict` exits 1 on a DRAFT for CI. `--draft` is kept as a no-op.

/** The citation gate, when the audited tree is here to check against. */
export function groundingOf(dossier: Dossier, run: string): { ok: boolean; dangling: number } | undefined {
  const repo = dossier.manifest.repo;
  try {
    if (!repo || !existsSync(repo) || !statSync(repo).isDirectory()) return undefined;
  } catch {
    return undefined;
  }
  const ck = check(dossier, { repo, run });
  return { ok: ck.ok, dangling: ck.dangling.length };
}

export function runRender(args: ParsedArgs): number {
  const run = resolve(flagStr(args, "run") ?? ".ultrasec");
  let dossier: ReturnType<typeof loadDossier>;
  try {
    dossier = loadDossier(run);
  } catch (e) {
    eprintln(`ultrasec render: ${(e as Error).message}`);
    return 2;
  }

  const legacy = flagBool(args, "legacy");
  const explicit = flagStr(args, "narrative");
  const nr = runNarrative(run, dossier, explicit ? resolve(explicit) : undefined);
  if (nr.error) {
    eprintln(`ultrasec render: ${nr.error}`);
    return 2;
  }
  const narrative: Narrative | undefined = nr.narrative;

  const out = deliverReport(run, dossier, {
    html: flagBool(args, "html"),
    md: flagBool(args, "md"),
    full: flagBool(args, "full"),
    legacy,
    narrative,
    grounding: legacy ? undefined : groundingOf(dossier, run),
  });

  println(`ultrasec render → ${out.written.join(" · ")}`);
  if (!legacy) println(`  status: ${statusLine(dossier, out.status)}`);
  if (narrative) {
    println(
      `  + narrative folded in (${narrative.remediations?.length ?? 0} fix(es), ${narrative.attackChains?.length ?? 0} chain(s), ${narrative.rootCauses?.length ?? 0} root-cause group(s)${narrative.executiveSummary ? ", exec summary" : ""}${narrative.positivePatterns ? ", positive patterns" : ""}${narrative.hardeningNotes?.length ? `, ${narrative.hardeningNotes.length} hardening note(s)` : ""})`,
    );
  } else if (explicit) {
    println(`  ⚠️  narrative had no sections grounded on confirmed findings — report rendered without it`);
  }
  if (out.removed.length) println(`  removed stale: ${out.removed.join(", ")}`);

  const unread = unadjudicatedCode(dossier.findings);
  const scannerPolicy = dossier.manifest.scannerPolicy;
  const scannerIncomplete = !!scannerPolicy && !scannerPolicy.complete;
  if (scannerPolicy && scannerIncomplete) {
    println(`  Required scanners incomplete: ${scannerPolicy.incomplete.join(", ")} — report marked incomplete.`);
  }
  if (unread.length) {
    const crit = unread.filter((f) => f.severity === "critical").length;
    println(`  ⚠️  ${unread.length} source-code candidate(s) at HIGH+ were never read (${crit} critical) — the report says so in a banner.`);
    println(
      `      next: ultrasec paths --run ${run} --surface code  →  ultrasec dossier <id> --run ${run}  →  ultrasec verify --apply verdicts.json --run ${run}`,
    );
  }
  // A report was written: exit 0, and the DRAFT banner is what travels.
  // `--strict` makes a DRAFT a failing exit (CI); `--draft` is still accepted
  // and changes nothing, since a written draft no longer fails.
  const draft = legacy ? unread.length > 0 || scannerIncomplete : out.status.draft;
  if (draft && flagBool(args, "strict")) {
    println(`      --strict: exit 1 on a DRAFT report.`);
    return 1;
  }
  return 0;
}
