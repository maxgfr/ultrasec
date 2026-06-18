import { resolve, join } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { flagStr, flagBool, println, eprintln, byStr, type ParsedArgs } from "../util.js";
import { importDeepsec } from "../tools/deepsec.js";
import { correlate } from "../tools/correlate.js";
import { enrichFindings } from "../tools/scoring.js";
import { addProvenance } from "../provenance.js";
import { buildGraph } from "../graph.js";
import { writeDossier, loadDossier, countBySeverity, type Dossier } from "../store.js";
import { VERSION, SCHEMA_VERSION, type Finding, type Manifest } from "../types.js";

// `ultrasec import <findings.json> --run <dir> [--format deepsec-json]
//   [--no-enrich/--offline] [--blame] [--json]`
//
// Ingest an UPSTREAM AI scanner's exported findings (vercel-labs/deepsec today)
// into an ultrasec dossier. ultrasec NEVER runs deepsec — the user produces the
// export themselves (`deepsec export --format json`); this is pure data ingest,
// so ultrasec's no-keys / zero-dep contract is untouched. The imported findings
// flow through the SAME correlate → EPSS/KEV risk-rank → grounding-gate → verify
// → render pipeline as every other source, making ultrasec the deterministic
// referee over deepsec's non-deterministic agent output.
export async function runImport(args: ParsedArgs): Promise<number> {
  const file = args._[1] ?? flagStr(args, "file");
  if (!file) {
    eprintln("ultrasec import: need a findings file — `ultrasec import <findings.json> --run <dir>`.");
    return 2;
  }
  const run = resolve(flagStr(args, "run") ?? ".ultrasec");
  const format = flagStr(args, "format") ?? "deepsec-json";
  if (format !== "deepsec-json") {
    eprintln(`ultrasec import: unknown --format '${format}' (supported: deepsec-json).`);
    return 2;
  }

  let raw: string;
  try {
    raw = readFileSync(resolve(file), "utf8");
  } catch (e) {
    eprintln(`ultrasec import: cannot read ${file} (${e instanceof Error ? e.message : String(e)}).`);
    return 2;
  }

  const imported = importDeepsec(raw);
  if (!imported.length) {
    eprintln(`ultrasec import: no findings parsed from ${file} (empty or unrecognized deepsec export).`);
    return 1;
  }

  // Fold into an existing run when present (preserving prior adjudications), else
  // start a fresh dossier from the imported findings alone (empty graph).
  let prev: Dossier | undefined;
  if (existsSync(join(run, "findings.json"))) {
    try {
      prev = loadDossier(run);
    } catch (e) {
      eprintln(`ultrasec import: existing dossier at ${run} is unreadable (${e instanceof Error ? e.message : String(e)}).`);
      return 2;
    }
  }

  const prevFindings = prev?.findings ?? [];
  // Correlate the deepsec findings against any engine/scanner findings already in
  // the run — corroboration (same category + cwe|title + file:line) unions sources[].
  const correlated = correlate([...prevFindings, ...imported]);

  const repo = prev?.manifest.repo ?? resolve(flagStr(args, "repo") ?? ".");
  const enrichOn = !(flagBool(args, "no-enrich") || flagBool(args, "offline"));
  const { findings: enriched, note: riskNote } = await enrichFindings(correlated, { enabled: enrichOn });

  // Opt-in provenance (needs the repo on disk; offline-tolerant).
  const blameOn = flagBool(args, "blame") || flagBool(args, "provenance");
  const withProv = blameOn ? addProvenance(enriched, repo, { blame: true }) : enriched;

  // Preserve prior adjudications by id (mirrors mergeDossier's lifecycle policy):
  // a finding the human/AI already ruled on keeps its status/verdict.
  const prevById = new Map(prevFindings.map((f) => [f.id, f]));
  const findings = withProv
    .map((f): Finding => {
      const old = prevById.get(f.id);
      return old && old.status !== "open"
        ? { ...f, status: old.status, verdict: old.verdict, exploitPath: old.exploitPath, confidence: old.confidence, message: old.message }
        : f;
    })
    .sort((a, b) => byStr(a.id, b.id));

  const graph = prev?.graph ?? buildGraph({ repo, files: [] });
  const toolsRun = [...new Set([...(prev?.manifest.toolsRun ?? []), "deepsec"])].sort();
  const manifest: Manifest = {
    version: VERSION,
    schemaVersion: SCHEMA_VERSION,
    repo,
    generatedNote: prev?.manifest.generatedNote ?? "Imported deepsec findings, correlated + risk-ranked by ultrasec. Adjudicate each before trusting it.",
    languages: prev?.manifest.languages ?? [],
    toolsRun,
    counts: { findings: findings.length, bySeverity: countBySeverity(findings) },
    ...(prev?.manifest.truncation ? { truncation: prev.manifest.truncation } : {}),
    ...(prev?.manifest.scopes && prev.manifest.scopes.length ? { scopes: prev.manifest.scopes } : {}),
  };

  writeDossier(run, { manifest, findings, graph });

  const added = findings.length - prevFindings.length;
  if (flagBool(args, "json")) {
    println(JSON.stringify({ run, parsed: imported.length, totalFindings: findings.length, added, toolsRun, risk: riskNote }, null, 2));
    return 0;
  }
  println(`ultrasec import → ${run}`);
  println(`  parsed ${imported.length} deepsec finding(s); dossier now holds ${findings.length} (${added >= 0 ? "+" : ""}${added} after correlation)`);
  println(`  ${riskNote}`);
  println(`  deepsec output is non-deterministic — each imported finding starts \`open\` and is yours to adjudicate.`);
  println(`  next: read ${run}/DOSSIER.md, \`ultrasec dossier <id>\`, then \`ultrasec verify\` + \`ultrasec check --semantic\`.`);
  return 0;
}
