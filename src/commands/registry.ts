import type { ParsedArgs } from "../util.js";
import { runTools } from "./tools.js";
import { runGraph } from "./graph.js";
import { runMap } from "./map.js";
import { runScan } from "./scan.js";
import { runContext } from "./context.js";
import { runImport } from "./import.js";
import { runLogs } from "./logs.js";
import { runDossier } from "./dossier.js";
import { runTriage } from "./triage.js";
import { runInvestigate } from "./investigate.js";
import { runPaths } from "./paths.js";
import { runVerify } from "./verify.js";
import { runRevalidate } from "./revalidate.js";
import { runVariants } from "./variants.js";
import { runGuards } from "./guards.js";
import { runAssumptions } from "./assumptions.js";
import { runCoverage } from "./coverage.js";
import { runNarrative } from "./narrative.js";
import { runImplement } from "./implement.js";
import { runCheck } from "./check.js";
import { runRender } from "./render.js";
import { runClean } from "./clean.js";
import { runRun } from "./run.js";
import { runOrchestrate } from "./orchestrate.js";
import { runProbe } from "./probe.js";
import { runRoute } from "./route.js";

// The command table, in its own module so both front-ends can reach it.
//
// It used to live in cli.ts. The MCP server calls these same handlers — that is
// the point, so a tool result and a CLI run cannot disagree — and importing
// cli.ts to get them would close a cycle: cli.ts → mcp/stdio.ts → mcp/server.ts
// → mcp/handlers.ts → cli.ts. ESM tolerates that cycle only by accident of
// evaluation order; a table both sides import instead does not depend on luck.

export type CommandHandler = (args: ParsedArgs) => number | Promise<number>;

export const COMMAND_HANDLERS: Record<string, CommandHandler> = {
  tools: runTools,
  graph: runGraph,
  map: runMap,
  scan: runScan,
  context: runContext,
  import: runImport,
  logs: runLogs,
  dossier: runDossier,
  triage: runTriage,
  paths: runPaths,
  verify: runVerify,
  investigate: runInvestigate,
  revalidate: runRevalidate,
  variants: runVariants,
  guards: runGuards,
  assumptions: runAssumptions,
  coverage: runCoverage,
  narrative: runNarrative,
  implement: runImplement,
  check: runCheck,
  render: runRender,
  clean: runClean,
  run: runRun,
  orchestrate: runOrchestrate,
  probe: runProbe,
  route: runRoute,
};
