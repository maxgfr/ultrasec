import { VERSION } from "./types.js";
import { parseArgs, flagBool, println, eprintln, type ParsedArgs } from "./util.js";
import { runTools } from "./commands/tools.js";
import { runGraph } from "./commands/graph.js";
import { runScan } from "./commands/scan.js";
import { runDossier } from "./commands/dossier.js";
import { runPaths } from "./commands/paths.js";
import { runVerify } from "./commands/verify.js";
import { runCheck } from "./commands/check.js";
import { runRender } from "./commands/render.js";

const HELP = `ultrasec ${VERSION} — cross-file security audit (taint + AI + tool orchestration)

A deterministic, zero-dependency engine builds a cross-file/function link-graph,
enumerates candidate source→sink taint paths, orchestrates best-in-class OSS
scanners, and prepares evidence packets; the AI does the security reasoning and
adversarially verifies each finding into a cited, tiered report.

USAGE
  ultrasec <command> [options]

COMMANDS
  scan       Scan a repo: detect stack, run available tools, build the link-graph,
             enumerate candidate taint paths, write the audit dossier.
  tools      List known external scanners, which are installed, and how to get them.
  graph      Show the links into/out of a file or symbol.
  paths      List candidate cross-file source→sink chains.
  dossier    Print the grounding packet for one finding (real code + neighbours).
  verify     Emit / apply the adversarial finding↔evidence worklist.
  render     Render SUMMARY/REPORT/FULL.md + a self-contained index.html.
  check      Gate: every finding must cite resolvable [file:line] (anti-hallucination);
             --semantic also folds in the verify verdicts.

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
    case "scan":
      return runScan(args);
    case "dossier":
      return runDossier(args);
    case "paths":
      return runPaths(args);
    case "verify":
      return runVerify(args);
    case "check":
      return runCheck(args);
    case "render":
      return runRender(args);
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
