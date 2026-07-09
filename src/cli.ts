import { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { VERSION } from "./types.js";
import { parseArgs, flagBool, println, eprintln, type ParsedArgs } from "./util.js";
import { runTools } from "./commands/tools.js";
import { runGraph } from "./commands/graph.js";
import { runMap } from "./commands/map.js";
import { runScan } from "./commands/scan.js";
import { runContext } from "./commands/context.js";
import { runImport } from "./commands/import.js";
import { runDossier } from "./commands/dossier.js";
import { runTriage } from "./commands/triage.js";
import { runInvestigate } from "./commands/investigate.js";
import { runPaths } from "./commands/paths.js";
import { runVerify } from "./commands/verify.js";
import { runRevalidate } from "./commands/revalidate.js";
import { runNarrative } from "./commands/narrative.js";
import { runImplement } from "./commands/implement.js";
import { runCheck } from "./commands/check.js";
import { runRender } from "./commands/render.js";
import { runClean } from "./commands/clean.js";
import { runRun } from "./commands/run.js";
import { runOrchestrate } from "./commands/orchestrate.js";

export const HELP = `ultrasec ${VERSION} — cross-file security audit (taint + AI + tool orchestration)

A deterministic, zero-dependency engine builds a cross-file/function link-graph,
enumerates candidate source→sink taint paths, orchestrates best-in-class OSS
scanners, and prepares evidence packets; the AI does the security reasoning and
adversarially verifies each finding into a cited, tiered report.

USAGE
  ultrasec <command> [options]

COMMANDS
  map        Cheap attack-surface recon: where untrusted input enters + what sinks
             exist, with suggested scoped targets. No taint BFS, no tools, no
             network — fast on huge repos. Flags: --scope · --out · --json.
  context    Project-context primer: emit a deterministic scaffold (frameworks,
             entry points, auth middleware, sanitizers) + a brief; you author
             CONTEXT.md, which is injected into every dossier + verify worklist.
             Highest-leverage first step. Flags: --repo · --out · --scope · --json.
  scan       Scan a repo: detect stack, run available tools (correlated across
             scanners), build the link-graph, enumerate candidate taint paths,
             rank by EPSS/KEV/CVSS risk, write the audit dossier.
             Flags: --tools auto|none|a,b · --docker · --no-enrich/--offline ·
             --sinks (orphan-sink recall) · --blame (git-blame/CODEOWNERS provenance) ·
             --scope/--include/--exclude/--max-files/--gitignore (focus) ·
             --budget quick|standard|thorough · --max-candidates · --max-depth ·
             --diff <ref>/--since <commit> · --merge · --resume (incremental).
  import     Ingest an upstream AI scanner's exported findings (deepsec) into the
             dossier: map → correlate → risk-rank → fold in (preserving verdicts).
             ultrasec never runs it — data ingest only. Flags: --run · --format
             deepsec-json · --no-enrich/--offline · --blame.
  tools      List known external scanners, which are installed, and how to get them.
  graph      Show the links into/out of a file or symbol.
  paths      List candidate cross-file source→sink chains.
  dossier    Print the grounding packet for one finding (real code + neighbours).
  triage     Fast, code-free first pass over OPEN candidates: emit / apply
             noise|keep. 'noise' dismisses only low/med/info; on high/critical
             it is ignored (kept open for verify). Flags: --run · --apply.
  verify     Emit / apply the adversarial finding↔evidence worklist.
  investigate Agentic discovery: emit an attack-surface-region worklist (entry/
             sink files + graph neighbours); --apply ingests grounded Discovery[]
             as 'ultrasec-ai' open candidates (citation-checked, dedup-folded into
             existing findings' sources). Flags: --run · --repo · --apply · --scope.
  revalidate Git-history false-positive cut: emit compact git facts (does the
             cited line still exist? when did it last change?) for confirmed /
             needs-human findings; --apply folds in still-valid/fixed/
             false-positive/uncertain (fixed → dismissed + fixed-in commit;
             high-sev false-positive → needs-human). Flags: --run · --repo · --apply.
  narrative  Emit the report-narrative worklist (reportable findings + a Narrative
             scaffold); you author NARRATIVE.json, folded in via 'render --narrative'.
  implement  Emit a remediation-PRD draft (IMPLEMENT.md) + a structured worklist
             (IMPLEMENT.todo.json) from confirmed (→ fix) / needs-human (→ investigate)
             findings, folding the grounded NARRATIVE.json (fixes, patches, root causes)
             when present. Emit-only — never changes a finding's status. Feed IMPLEMENT.md
             to the 'to-prd' skill or an implementer. Flags: --run · --narrative <file> · --json.
  render     Render SUMMARY/REPORT.md + a self-contained index.html.
             --narrative <file> folds in AI-authored sections (exec summary, fixes,
             attack chains, root causes), clearly marked + grounding-checked.
  check      Gate: every finding must cite resolvable [file:line] (anti-hallucination);
             --semantic also folds in the verify verdicts.
  clean      Remove the intermediate scan artifacts, KEEPING the rendered
             deliverables (REPORT/SUMMARY/index.html + findings.json); --all wipes
             the whole run dir, --keep-output keeps everything. With --docker also
             removes the scanner images + toolbox image + trivy cache volume
             (--dry-run to preview).
  run        Orchestrate the AI stages (context → triage → investigate → verify →
             revalidate → narrative → implement → check → render). DEFAULT makes ZERO external
             calls: scans + emits every worklist + prints the agent TODO. --powered
             drives an agent CLI per worklist (keys live in that CLI, not ultrasec);
             --cross-check <cli> escalates high/critical verify/revalidate
             disagreement to needs-human. Flags: --repo · --out · --powered ·
             --agent <name|tpl> · --cross-check <name|tpl> · --stages · --no-scan.
  orchestrate Emit the run's multi-agent orchestration from its CURRENT worklists
             into <run>/orchestration/: one <phase>.workflow.mjs per ready phase
             (adjudicate | verify | revalidate | investigate, real ids batched
             8/agent), the dispatch contracts (agents/<role>.md) and a sequential
             RUNBOOK.md fallback. Subagents RETURN verdict/discovery fragments;
             every conservative --apply fold stays with you (one writer).
             Flags: --run · --phase <name> · --eco (runbook + contracts only) ·
             --list (phase status as JSON).

GLOBAL
  --help, -h     Show this help.
  --version, -v  Print the version.
  --json         Machine-readable output (where supported).

Each command's flags are listed above; \`--help\`/\`-h\` (anywhere) prints this help.
`;

// Single source of truth for the command→handler mapping. The test-suite asserts
// every command named in HELP has an entry here (and vice-versa), so the help
// text can never drift from what actually dispatches.
type CommandHandler = (args: ParsedArgs) => number | Promise<number>;
export const COMMAND_HANDLERS: Record<string, CommandHandler> = {
  tools: runTools,
  graph: runGraph,
  map: runMap,
  scan: runScan,
  context: runContext,
  import: runImport,
  dossier: runDossier,
  triage: runTriage,
  paths: runPaths,
  verify: runVerify,
  investigate: runInvestigate,
  revalidate: runRevalidate,
  narrative: runNarrative,
  implement: runImplement,
  check: runCheck,
  render: runRender,
  clean: runClean,
  run: runRun,
  orchestrate: runOrchestrate,
};

export async function dispatch(cmd: string | undefined, args: ParsedArgs): Promise<number> {
  if (cmd === undefined || cmd === "help") {
    println(HELP);
    return 0;
  }
  if (cmd === "version") {
    println(VERSION);
    return 0;
  }
  const handler = COMMAND_HANDLERS[cmd];
  if (!handler) {
    eprintln(`ultrasec: unknown command \`${cmd}\`. Run \`ultrasec --help\`.`);
    return 2;
  }
  return handler(args);
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const args = parseArgs(argv);

  if (flagBool(args, "help") || args.flags.h === true) {
    println(HELP);
    process.exit(0);
  }
  if (flagBool(args, "version") || args.flags.v === true) {
    println(VERSION);
    process.exit(0);
  }

  const code = await dispatch(args._[0], args);
  process.exit(code);
}

// Only auto-run when this bundle is the process entry point — never when a test
// imports it for HELP / dispatch / COMMAND_HANDLERS. realpathSync resolves the
// `.bin` symlink npm/npx creates so `npx ultrasec` still matches import.meta.url.
function isEntrypoint(): boolean {
  const argv1 = process.argv[1];
  if (!argv1) return false;
  try {
    return import.meta.url === pathToFileURL(realpathSync(argv1)).href;
  } catch {
    return false;
  }
}

if (isEntrypoint()) {
  main().catch((err) => {
    eprintln(`ultrasec: ${err instanceof Error ? err.stack || err.message : String(err)}`);
    process.exit(1);
  });
}
