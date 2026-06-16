import { resolve } from "node:path";
import { flagStr, flagBool, println, eprintln, byStr, type ParsedArgs } from "../util.js";
import { scanRepo } from "../scan.js";
import { buildGraph } from "../graph.js";
import { enumerateTaint } from "../taint.js";
import { orchestrate } from "../tools/run.js";
import { ADAPTERS } from "../tools/index.js";
import { writeDossier, countBySeverity, type Dossier } from "../store.js";
import { VERSION, SCHEMA_VERSION, type Finding, type Manifest } from "../types.js";

// `ultrasec scan --repo <dir> [--out .ultrasec] [--json]`
// The mechanical pass: scan → build link-graph → enumerate cross-file taint
// candidates → write the audit dossier. (External tools wired in M4.)
export function runScan(args: ParsedArgs): number {
  const repo = resolve(flagStr(args, "repo") ?? ".");
  const out = resolve(flagStr(args, "out") ?? ".ultrasec");

  const scan = scanRepo(repo);
  const graph = buildGraph(scan);
  const taintFindings = enumerateTaint(scan, graph);

  // External tools: `--tools none`/`--no-tools` skips; `--tools a,b` selects;
  // anything else (incl. absent) = auto-run every installed scanner.
  const toolsFlag = flagStr(args, "tools");
  const skipTools = flagBool(args, "no-tools") || toolsFlag === "none";
  const which = toolsFlag && toolsFlag !== "auto" && toolsFlag !== "none" ? toolsFlag.split(",").map((s) => s.trim()) : undefined;
  const tool = skipTools ? { findings: [] as Finding[], toolsRun: [] as string[], results: [] } : orchestrate(ADAPTERS, repo, which);

  // Merge taint candidates with tool findings (ids are disjoint by construction).
  const findings = [...taintFindings, ...tool.findings].sort((a, b) => byStr(a.id, b.id));

  const languages = [...new Set(scan.files.map((f) => f.lang))].sort();
  const manifest: Manifest = {
    version: VERSION,
    schemaVersion: SCHEMA_VERSION,
    repo,
    generatedNote: "Taint candidates are deterministic; external-tool results depend on installed scanners.",
    languages,
    toolsRun: tool.toolsRun,
    counts: { findings: findings.length, bySeverity: countBySeverity(findings) },
  };

  const dossier: Dossier = { manifest, findings, graph };
  writeDossier(out, dossier);

  if (flagBool(args, "json")) {
    println(JSON.stringify({ out, counts: manifest.counts, languages, files: scan.files.length, toolsRun: tool.toolsRun }, null, 2));
    return 0;
  }

  const c = manifest.counts.bySeverity;
  println(`ultrasec scan → ${out}`);
  println(`  files scanned: ${scan.files.length}  ·  languages: ${languages.join(", ") || "—"}`);
  if (!skipTools) {
    println(`  external tools run: ${tool.toolsRun.join(", ") || "none"}  (\`ultrasec tools\` to see/install more)`);
  }
  println(`  candidate findings: ${findings.length}  (crit ${c.critical} · high ${c.high} · med ${c.medium} · low ${c.low})  ·  ${taintFindings.length} taint + ${tool.findings.length} tool`);
  if (!findings.length) {
    println(`  no taint candidates — still review the DOSSIER and run external tools (\`ultrasec tools\`).`);
  } else {
    println(`  next: read ${out}/DOSSIER.md, then \`ultrasec dossier <id> --run ${out}\` to adjudicate.`);
  }
  return 0;
}
