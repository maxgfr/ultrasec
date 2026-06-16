import { resolve } from "node:path";
import { flagStr, flagBool, println, eprintln, type ParsedArgs } from "../util.js";
import { scanRepo } from "../scan.js";
import { buildGraph } from "../graph.js";
import { enumerateTaint } from "../taint.js";
import { writeDossier, countBySeverity, type Dossier } from "../store.js";
import { VERSION, SCHEMA_VERSION, type Manifest } from "../types.js";

// `ultrasec scan --repo <dir> [--out .ultrasec] [--json]`
// The mechanical pass: scan → build link-graph → enumerate cross-file taint
// candidates → write the audit dossier. (External tools wired in M4.)
export function runScan(args: ParsedArgs): number {
  const repo = resolve(flagStr(args, "repo") ?? ".");
  const out = resolve(flagStr(args, "out") ?? ".ultrasec");

  const scan = scanRepo(repo);
  const graph = buildGraph(scan);
  const findings = enumerateTaint(scan, graph);

  const languages = [...new Set(scan.files.map((f) => f.lang))].sort();
  const manifest: Manifest = {
    version: VERSION,
    schemaVersion: SCHEMA_VERSION,
    repo,
    generatedNote: "Deterministic: re-scanning an unchanged repo yields the same findings.",
    languages,
    toolsRun: [], // external tools are added in M4
    counts: { findings: findings.length, bySeverity: countBySeverity(findings) },
  };

  const dossier: Dossier = { manifest, findings, graph };
  writeDossier(out, dossier);

  if (flagBool(args, "json")) {
    println(JSON.stringify({ out, counts: manifest.counts, languages, files: scan.files.length }, null, 2));
    return 0;
  }

  const c = manifest.counts.bySeverity;
  println(`ultrasec scan → ${out}`);
  println(`  files scanned: ${scan.files.length}  ·  languages: ${languages.join(", ") || "—"}`);
  println(`  candidate findings: ${findings.length}  (crit ${c.critical} · high ${c.high} · med ${c.medium} · low ${c.low})`);
  if (!findings.length) {
    println(`  no taint candidates — still review the DOSSIER and run external tools (\`ultrasec tools\`).`);
  } else {
    println(`  next: read ${out}/DOSSIER.md, then \`ultrasec dossier <id> --run ${out}\` to adjudicate.`);
  }
  return 0;
}
