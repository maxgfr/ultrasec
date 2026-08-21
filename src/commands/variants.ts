import { writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { flagStr, flagBool, println, eprintln, type ParsedArgs } from "../util.js";
import { loadDossier } from "../store.js";
import { emitWorklist, readApply, persistFindings, stageFiles } from "../stage.js";
import { surfaceDropped } from "../apply-parse.js";
import { loadContextDoc } from "../context.js";
import { ingestDiscoveries } from "../investigate.js";
import { buildVariantWorklist, renderVariantsMd, parseVariantResults, renderRegressionRules } from "../variants.js";

// `ultrasec variants --run <dir>`                          → emit the hunt worklist
// `ultrasec variants --apply <file|dir|a,b,c> --run <dir>` → fold the variants in
//
// Seeds are CONFIRMED findings only. Variants fold in through the SAME
// citation-gated path as `investigate` discoveries, so a variant that cites a
// line which does not resolve is rejected exactly like any other invented
// location — the hunt cannot lower the grounding bar.
export function runVariants(args: ParsedArgs): number {
  const run = resolve(flagStr(args, "run") ?? ".ultrasec");
  let dossier: ReturnType<typeof loadDossier>;
  try {
    dossier = loadDossier(run);
  } catch (e) {
    eprintln(`ultrasec variants: ${(e as Error).message}`);
    return 2;
  }
  const repo = resolve(flagStr(args, "repo") ?? dossier.manifest.repo);

  const applyPath = flagStr(args, "apply");
  if (applyPath) {
    let parsed: ReturnType<typeof parseVariantResults>;
    try {
      parsed = readApply(applyPath, /variant.*\.json$/i, parseVariantResults);
    } catch (e) {
      eprintln(`ultrasec variants: cannot read variant results at ${(e as Error).message}`);
      return 2;
    }
    const strict = flagBool(args, "strict");

    const known = new Set(dossier.findings.filter((f) => f.status === "confirmed").map((f) => f.id));
    const stale = parsed.rows.filter((r) => !known.has(r.seedId)).map((r) => r.seedId);
    if (stale.length === parsed.rows.length && parsed.rows.length > 0) {
      eprintln(
        `ultrasec variants --apply: all ${stale.length} result(s) name a seed that is not a confirmed finding (${stale.join(", ")}) — stale fragment? Re-emit (\`variants --run ${run}\`); nothing was folded.`,
      );
      return 2;
    }

    const discoveries = parsed.rows.flatMap((r) => r.variants ?? []);
    const res = ingestDiscoveries(dossier, discoveries, repo, { context: loadContextDoc(run) });
    persistFindings(run, dossier, res.findings);

    // The audit stops being a document here: a finding is fixed once, a rule
    // keeps it fixed. Written only when the auditor actually authored rules.
    const rules = renderRegressionRules(parsed.rows);
    const rulePath = join(run, "ultrasec-variants.yaml");
    if (rules) writeFileSync(rulePath, rules);

    if (flagBool(args, "json")) {
      println(
        JSON.stringify(
          { ingested: res.ingested, folded: res.folded, rejected: res.rejected, stale, rules: rules ? rulePath : null, dropped: parsed.dropped },
          null,
          2,
        ),
      );
      return strict && (parsed.dropped.length > 0 || res.rejected.length > 0) ? 1 : 0;
    }
    println(`ultrasec variants --apply → updated ${run}/findings.json`);
    println(`  ${res.ingested} variant(s) ingested · ${res.folded} folded into an existing finding · ${res.rejected.length} rejected`);
    for (const r of res.rejected) println(`  ✗ ${r.discovery.file}:${r.discovery.line} — ${r.reason}`);
    if (stale.length) println(`  ${stale.length} result(s) named a non-confirmed seed (ignored): ${stale.join(", ")}`);
    if (rules) println(`  regression rules → ${rulePath}  (semgrep --config ${rulePath})`);
    return surfaceDropped(parsed.dropped, strict, println);
  }

  const items = buildVariantWorklist(dossier);
  const todoPath = emitWorklist(run, stageFiles("VARIANTS"), items, renderVariantsMd(items, loadContextDoc(run)));

  if (flagBool(args, "json")) {
    println(JSON.stringify(items, null, 2));
    return 0;
  }
  println(`ultrasec variants → ${todoPath} (${items.length} seed${items.length === 1 ? "" : "s"})`);
  if (!items.length) {
    println(`  no confirmed findings yet — variants are hunted from proved bugs, not candidates.`);
    println(`  run \`ultrasec verify --apply <verdicts> --run ${run}\` first.`);
  } else {
    const n = items.reduce((a, i) => a + i.neighbours.length, 0);
    println(`  ${n} mechanical neighbour(s) pre-listed — places to look, not findings.`);
    println(`  state each root cause, generalize ONE dimension at a time, then:`);
    println(`  ultrasec variants --apply VARIANTS.json --run ${run}`);
  }
  return 0;
}
