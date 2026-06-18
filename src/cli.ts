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
import { runPaths } from "./commands/paths.js";
import { runVerify } from "./commands/verify.js";
import { runRevalidate } from "./commands/revalidate.js";
import { runNarrative } from "./commands/narrative.js";
import { runCheck } from "./commands/check.js";
import { runRender } from "./commands/render.js";
import { runClean } from "./commands/clean.js";

const HELP = `ultrasec ${VERSION} — cross-file security audit (taint + AI + tool orchestration)

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
  revalidate Git-history false-positive cut: emit compact git facts (does the
             cited line still exist? when did it last change?) for confirmed /
             needs-human findings; --apply folds in still-valid/fixed/
             false-positive/uncertain (fixed → dismissed + fixed-in commit;
             high-sev false-positive → needs-human). Flags: --run · --repo · --apply.
  narrative  Emit the report-narrative worklist (reportable findings + a Narrative
             scaffold); you author NARRATIVE.json, folded in via 'render --narrative'.
  render     Render SUMMARY/REPORT/FULL.md + a self-contained index.html.
             --narrative <file> folds in AI-authored sections (exec summary, fixes,
             attack chains, root causes), clearly marked + grounding-checked.
  check      Gate: every finding must cite resolvable [file:line] (anti-hallucination);
             --semantic also folds in the verify verdicts.
  clean      Remove the audit dossier and, with --docker, the scanner images +
             toolbox image + trivy cache volume (--dry-run to preview).

GLOBAL
  --help, -h     Show this help.
  --version, -v  Print the version.
  --json         Machine-readable output (where supported).

Run \`ultrasec <command> --help\` for command-specific options.
`;

async function dispatch(cmd: string | undefined, args: ParsedArgs): Promise<number> {
  switch (cmd) {
    case undefined:
    case "help":
      println(HELP);
      return 0;
    case "version":
      println(VERSION);
      return 0;
    case "tools":
      return runTools(args);
    case "graph":
      return runGraph(args);
    case "map":
      return runMap(args);
    case "scan":
      return runScan(args);
    case "context":
      return runContext(args);
    case "import":
      return runImport(args);
    case "dossier":
      return runDossier(args);
    case "triage":
      return runTriage(args);
    case "paths":
      return runPaths(args);
    case "verify":
      return runVerify(args);
    case "revalidate":
      return runRevalidate(args);
    case "narrative":
      return runNarrative(args);
    case "check":
      return runCheck(args);
    case "render":
      return runRender(args);
    case "clean":
      return runClean(args);
    default:
      eprintln(`ultrasec: unknown command \`${cmd}\`. Run \`ultrasec --help\`.`);
      return 2;
  }
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

main().catch((err) => {
  eprintln(`ultrasec: ${err instanceof Error ? err.stack || err.message : String(err)}`);
  process.exit(1);
});
