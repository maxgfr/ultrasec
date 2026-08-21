import { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { warmGrammars } from "./vendor/codeindex-engine.mjs";
import { VERSION } from "./types.js";
import { parseArgs, flagBool, flagStr, numFlag, println, eprintln, type ParsedArgs } from "./util.js";
import { teeOutput } from "./util.js";
import { extname } from "node:path";
import { appendJournal, writeReport, UnknownReportFormat, REPORT_FORMATS, type Transcript } from "./transcript.js";
import { COMMAND_HANDLERS, type CommandHandler } from "./commands/registry.js";
import { runStdioServer } from "./mcp/stdio.js";
import { startHttpServer } from "./mcp/http.js";

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
             network — fast on huge repos. Writes MAP.md + attack-surface.json only
             when --out is given (else MAP.md goes to stdout). Flags: --repo ·
             --out · --scope/--include/--exclude/--max-files/--gitignore · --json.
  context    Project-context primer: emit a deterministic scaffold (frameworks,
             entry points, auth middleware, sanitizers) + a brief; you author
             CONTEXT.md, which is injected into every dossier + every stage worklist.
             Highest-leverage first step. Flags: --repo · --out ·
             --scope/--include/--exclude/--max-files/--gitignore · --json.
  scan       Scan a repo: detect stack, run available tools (correlated across
             scanners), build the link-graph, enumerate candidate taint paths,
             rank by EPSS/KEV/CVSS risk, write the audit dossier.
             Flags: --tools auto|none|a,b · --docker · --no-enrich/--offline ·
             --sinks (orphan-sink recall) · --log-hygiene (opt-in CWE-117/CWE-532
             logging-hygiene checks) · --blame (git-blame/CODEOWNERS provenance) ·
             --strict-scope (drop candidates whose source is in a DIFFERENT
             function of the same file) · --no-env-sources (drop env-rooted flows) ·
             --scope/--include/--exclude/--max-files/--gitignore (focus) ·
             --budget quick|standard|thorough · --max-candidates · --max-depth ·
             --diff <ref>/--since <commit> · --merge · --resume (incremental) ·
             --quiet (mute the stderr progress stream) · --json.
  import     Ingest an upstream AI scanner's exported findings (deepsec) into the
             dossier: map → correlate → risk-rank → fold in (preserving verdicts).
             ultrasec never runs it — data ingest only. Flags: <findings.json>|--file ·
             --run · --repo · --format deepsec-json · --no-enrich/--offline ·
             --blame/--provenance · --json.
  logs       Blue-team log forensics: ingest existing log files (nginx/access,
             JSON-lines, syslog/auth.log, generic-timestamped, raw) and run
             deterministic attack-signature detection (SQLi/XSS/traversal/
             cmdinj/probe-path + known scanner user-agents), per-IP behavioral
             aggregation (brute-force/credential-compromise, request bursts,
             scan/recon→hit), and secret/PII-leak detection into its OWN
             dossier, findings citing [logfile:line]. Evidence is redacted by
             default (secrets/PII never land in a finding message). --sigma
             emits a ready-to-deploy SIGMA detection pack (ultrasec-logs.sigma.yml)
             for those classes — the blue-team analogue of 'variants'. Flags:
             --out · --format · --budget quick|standard|thorough ·
             --max-lines · --window <sec> · --no-redact · --sigma · --json.
  tools      List known external scanners, which are installed, and how to get
             them. --upgrade drives each INSTALLED native tool's own package
             manager (brew/pipx/go/cargo/corepack/npm, inferred from its binary
             path) to latest; apt-owned/unknown origins print a hint instead —
             never sudo. Docker scans and package-checker already self-refresh.
             Flags: --upgrade · --dry-run (print the commands, run nothing) ·
             --json.
  graph      Show the links into/out of a file or symbol. Reads <run>/graph.json
             with --run, else live-scans --repo. Flags: <file|symbol> · --depth n
             (default 1) · --run · --repo · --json.
  paths      List candidate cross-file source→sink chains.
             Flags: --run · --kind <k> · --severity <s> · --json.
  dossier    Print the grounding packet for one finding (real code + neighbours).
             The id may be a unique PREFIX. Flags: <finding-id> · --run · --repo.
  triage     Fast, code-free first pass over OPEN candidates: emit / apply
             noise|keep. 'noise' dismisses only low/med/info; on high/critical
             it is ignored (kept open for verify). Flags: --run · --apply · --json.
  verify     Emit / apply the adversarial finding↔evidence worklist. --shards n
             --shard i splits the emit across fan-out workers, writing
             VERIFY.todo.<i>.json (the .md brief always covers the FULL worklist).
             --apply takes a file, a comma-list, or a DIRECTORY (picks up every
             *verdict*.json, sorted) and fails closed if every fragment is stale.
             The worklist is a DELTA: findings an earlier pass already adjudicated
             as needs-human are withheld until --all. --apply reports any verdict
             that changes an already-adjudicated finding; under --strict that
             fails unless --re-verdict is passed.
             Flags: --run · --shards · --shard · --apply · --json.
  investigate Agentic discovery: emit an attack-surface-region worklist (entry/
             sink files + graph neighbours); --apply ingests grounded Discovery[]
             as 'ultrasec-ai' open candidates (citation-checked, dedup-folded into
             existing findings' sources). --lens sharp-edges|access-control|idor|
             crypto|privacy|cloud asks a DIFFERENT question of the same regions
             (access-control: IDOR/BOLA/BFLA — the guard vs. the object returned;
             cloud: SSRF-to-metadata, over-broad IAM, container escape).
             Unenforced
             assumptions from 'assumptions' are folded into the region prompts.
             Flags: --run · --repo · --apply · --lens ·
             --scope/--include/--exclude/--max-files/--gitignore · --json.
  revalidate Git-history false-positive cut: emit compact git facts (does the
             cited line still exist? when did it last change?) for confirmed /
             needs-human findings; --apply folds in still-valid/fixed/
             false-positive/uncertain (fixed → dismissed + fixed-in commit;
             high-sev false-positive → needs-human), and fails closed if every
             fragment is stale. Flags: --run · --repo · --apply · --json.
  assumptions
             Build the assumption map BEFORE hunting: per unit, what it
             guarantees (cited) and what it depends on that nothing enforces.
             An assumption marked 'nothing-found' is a place the code trusts
             something nobody wrote down — the highest-value lead an audit
             produces, and one no taint walk can reach. --apply writes
             ASSUMPTIONS.md and hands the leads to the next 'investigate' emit.
             Flags: --run · --repo · --apply · --strict ·
             --scope/--include/--exclude/--max-files/--gitignore · --json.
  variants   Hunt other instances of a CONFIRMED bug's root cause: emit one seed
             per confirmed finding with its mechanical neighbours (same sink
             callee / file / CWE), you state the root cause and generalize a
             search one dimension at a time; --apply folds the variants in
             through the same citation gate as 'investigate' and writes the
             regression rules you authored to ultrasec-variants.yaml.
             Flags: --run · --repo · --apply · --strict · --json.
  narrative  Emit the report-narrative worklist (reportable findings + a Narrative
             scaffold); you author NARRATIVE.json, folded in via 'render --narrative'.
             Flags: --run · --json.
  implement  Emit a remediation-PRD draft (IMPLEMENT.md) + a structured worklist
             (IMPLEMENT.todo.json) from confirmed (→ fix) / needs-human (→ investigate)
             findings, folding the grounded NARRATIVE.json (fixes, patches, root causes)
             when present. Emit-only — never changes a finding's status. Feed IMPLEMENT.md
             to the 'to-prd' skill or an implementer. Flags: --run · --narrative <file> · --json.
  render     Render SUMMARY/REPORT.md + a self-contained index.html.
             --narrative <file> folds in AI-authored sections (exec summary, fixes,
             attack chains, root causes), clearly marked + grounding-checked.
  coverage   The honest complement to 'only report what you can exploit': a
             standards matrix of what this audit looked at and what it did NOT.
             A short report reads as "nothing there" when it means "nothing
             there, in what I looked at" — this separates the two, and names the
             categories no deterministic signal can cover so you answer them
             explicitly. --standard scores against ASVS (default), the OWASP
             Top 10, the OWASP API Top 10, MASVS or the CWE Top 25. Read-only.
             Flags: --run · --standard asvs|owasp-top10|owasp-api-top10|masvs|cwe-top25 ·
             --write (COVERAGE.md) · --json.
  check      Gate: every finding must cite resolvable [file:line] (anti-hallucination).
             READ-ONLY — it writes nothing and changes no status; --semantic ALSO
             fails when a candidate is still unadjudicated. Exit 0 ok · 1 gate
             failed · 2 unreadable run. Flags: --run · --repo · --semantic ·
             --min-severity critical|high|medium|low|info · --json.
  clean      Remove the intermediate scan artifacts, KEEPING the rendered
             deliverables (REPORT/SUMMARY/index.html + findings.json); --all wipes
             the whole run dir, --keep-output keeps everything. With --docker also
             removes the scanner images + toolbox image + trivy cache volume
             (--dry-run to preview). NOTE: CONTEXT.md, MAP.md, sbom.cdx.json,
             LOGSTATS.json, NARRATIVE.json, IMPLEMENT.md and orchestration/ count as
             intermediates; a run that was never rendered is removed whole.
             Flags: --run · --all · --keep-output · --docker · --dry-run · --json.
  run        Orchestrate the AI stages (context → assumptions → triage →
             investigate → verify → revalidate → variants → narrative →
             implement), then ALWAYS check + render. DEFAULT
             makes ZERO external calls: scans + emits every worklist + prints the agent
             TODO. --powered drives an agent CLI per worklist (keys live in that CLI,
             not ultrasec); --cross-check <cli> escalates high/critical verify/
             revalidate disagreement to needs-human. --stages selects a subset of the
             SEVEN stage names above — 'check'/'render' are unconditional post-steps
             and are NOT valid --stages tokens. Flags: --repo · --out · --powered ·
             --agent <name|tpl> · --cross-check <name|tpl> · --stages · --no-scan ·
             --scope/--include/--exclude/--max-files/--gitignore · --json.
  orchestrate Emit the run's multi-agent orchestration from its CURRENT worklists
             into <run>/orchestration/: one <phase>.workflow.mjs per ready phase
             (adjudicate | verify | revalidate | investigate, real ids batched
             8/agent), the dispatch contracts (agents/<role>.md) and a sequential
             RUNBOOK.md fallback. Subagents RETURN verdict/discovery fragments;
             every conservative --apply fold stays with you (one writer).
             Flags: --run · --phase <name> · --eco (runbook + contracts only) ·
             --list (phase status as JSON).
  mcp        Serve the audit over the Model Context Protocol, so a non-Claude-Code
             host (Cursor, Zed, Claude Desktop) gets the tools, the workflows as
             prompts, and SKILL.md + references/ as resources. Read-only unless
             --allow-write, which additionally exposes scan and clean.
             Flags: --transport stdio|http (default stdio) · --repo <dir> (a
             default repo makes it optional on every tool) · --allow-write ·
             --port <n> · --bind <addr> · --allow-origin <o,...> · --allow-remote ·
             --max-response-bytes <n>.
  probe      The ONE dynamic check, walled off from the static audit: observe a
             RUNNING site's posture on the wire — security headers, cookie flags,
             TLS, HTTP→HTTPS redirect, banners, a single crafted CORS preflight,
             optional GraphQL introspection. Read-only, single host, no crawl.
             Findings cite [response-header:…]/[cookie:…]/[tls]/[url:…] and go to
             PROBE.json/PROBE.md ONLY — never findings.json, so 'check' never sees
             them. Requires --i-own-this; refuses private/loopback targets unless
             --allow-private. Flags: --i-own-this · --allow-private · --deep ·
             --graphql · --timeout <ms> · --out · --strict · --json.
  route      Triage a target that is OUTSIDE ultrasec's scope: given a file
             (.apk/.ipa, .so/.exe/.dll, firmware, .pcap, .crx, .jar…) or an
             http(s):// URL, classify it and print the METHODOLOGY + recommended
             external tools (jadx, radare2/Ghidra/IDA, frida, binwalk, wireshark,
             nmap/nuclei/ZAP…). Advisory ONLY — runs nothing, no network, reads
             no target. In scope it routes back: a URL → 'probe', source/a repo →
             'scan'. Flags: --json · --write (ROUTE.md) · --out <dir>.

GLOBAL
  --help, -h     Show this help.
  --version, -v  Print the version.
  --json         Machine-readable output (every command above except render/dossier).
  --report <p>   ALSO archive this command's output to <p>; the extension picks the
                 format (.md, .html, .json, .txt/.log). stdout is unchanged; an
                 unknown extension exits 2 before the command runs.
  --no-journal   Don't append this command to <run>/JOURNAL.md (the append-only
                 record of every command run against an audit directory).
  --strict       On an --apply stage, exit 1 if any row was refused, so a partial
                 fold can't pass CI. (triage/verify/investigate/revalidate)

  --apply -      Read the payload from stdin instead of a path.

EXIT CODES
  0  ok        1  a gate failed (check) / nothing usable ingested (import)
                  / rows refused under --strict
  2  usage or runtime error (bad flag value, unreadable run, unresolvable git ref)

Each command's flags are listed above; \`--help\`/\`-h\` (anywhere) prints this help.
Full reference incl. artifacts written per command: skills/ultrasec/references/commands.md.
`;

// Single source of truth for the command→handler mapping. The test-suite asserts
// every command named in HELP has an entry here (and vice-versa), so the help
// text can never drift from what actually dispatches.
// The command table lives in commands/registry.ts, so the MCP server can reach
// the same handlers without importing this module.
export { COMMAND_HANDLERS, type CommandHandler };

export async function dispatch(cmd: string | undefined, args: ParsedArgs): Promise<number> {
  if (cmd === undefined || cmd === "help") {
    println(HELP);
    return 0;
  }
  if (cmd === "version") {
    println(VERSION);
    return 0;
  }
  // `mcp` is not in COMMAND_HANDLERS: that table maps a command to a function
  // that runs and returns an exit code, and this one blocks for the life of the
  // server. It also must never print to stdout, which every entry in that table
  // does by design.
  if (cmd === "mcp") return runMcp(args);
  const handler = COMMAND_HANDLERS[cmd];
  if (!handler) {
    eprintln(`ultrasec: unknown command \`${cmd}\`. Run \`ultrasec --help\`.`);
    return 2;
  }
  return handler(args);
}

// Serve the audit over the Model Context Protocol. Returns only when the
// server stops, so `dispatch` does not fall through while it is still running.
async function runMcp(args: ParsedArgs): Promise<number> {
  const transport = flagStr(args, "transport") ?? "stdio";
  if (transport !== "stdio" && transport !== "http") {
    eprintln(`ultrasec: invalid --transport "${transport}" (expected: stdio, http)`);
    return 2;
  }
  const maxResponseBytes = numFlag(args, "max-response-bytes");
  if (flagStr(args, "max-response-bytes") !== undefined && (maxResponseBytes === undefined || maxResponseBytes <= 0)) {
    eprintln("ultrasec: invalid --max-response-bytes");
    return 2;
  }
  const options = {
    // A default repo makes `repo` optional on every tool, for a server
    // dedicated to one project.
    defaultRun: flagStr(args, "repo"),
    allowWrite: flagBool(args, "allow-write"),
    maxResponseBytes,
  };

  if (transport === "stdio") {
    // Nothing is written to stdout here: from this point stdout carries
    // JSON-RPC frames only, and runStdioServer guards that.
    await runStdioServer(options);
    return 0;
  }

  const port = numFlag(args, "port") ?? 7340;
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    eprintln("ultrasec: invalid --port");
    return 2;
  }
  const allowOriginRaw = flagStr(args, "allow-origin");
  const allowOrigin = allowOriginRaw
    ? allowOriginRaw
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean)
    : undefined;
  let running: Awaited<ReturnType<typeof startHttpServer>>;
  try {
    running = await startHttpServer({ ...options, port, bind: flagStr(args, "bind"), allowOrigin, allowRemote: flagBool(args, "allow-remote") });
  } catch (e) {
    eprintln(`ultrasec: ${(e as Error).message}`);
    return 2;
  }
  // stderr, not stdout: an HTTP server's stdout is not a protocol stream, but
  // keeping the two transports identical here means no one has to remember
  // which is which.
  eprintln(`ultrasec: MCP server listening on ${running.url}`);
  eprintln(`  client: claude mcp add --transport http ultrasec ${running.url}`);
  for (const sig of ["SIGINT", "SIGTERM"] as const) {
    process.once(sig, () => {
      void running.close().then(() => process.exit(0));
    });
  }
  await new Promise<void>((res) => running.server.once("close", res));
  return 0;
}

// Commands that walk the repo and extract symbols. Only these pay for the
// grammar warm-up: `check`/`render`/`triage`/… re-read an existing dossier and
// must never trigger a 22 MB download to do it.
const SCANNING_COMMANDS = new Set(["scan", "run", "graph", "map", "context", "investigate", "logs"]);

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

  // Load the tree-sitter grammars ONCE, up front — the only async step; the scan
  // pipeline stays synchronous and parses against the warmed grammars. Without
  // this, `extractAst` never fires and every run silently uses the regex
  // extractors: on a 69-file TypeScript repo that is 27 taint candidates instead
  // of 66, and zero of the 9 critical cross-file command-injection candidates.
  // First use on a fresh machine pulls the wasm into the shared cache; offline ⇒
  // regex fallback, and warmGrammars says so rather than degrading in silence.
  if (SCANNING_COMMANDS.has(args._[0] ?? "")) await warmGrammars({ label: "ultrasec" });

  const code = await withArchiving(args, argv, () => dispatch(args._[0], args));
  process.exit(code);
}

/**
 * Commands that must leave the run directory untouched, and therefore never
 * journal into it.
 *
 * Two promises depend on this. `check` is the CI gate, documented as writing
 * nothing — a journal entry would be a write. And the orchestration contracts let
 * fan-out subagents run `dossier`/`graph`/`paths` precisely because they don't
 * write, with the orchestrator as the sole writer; several subagents appending to
 * one JOURNAL.md would break that.
 *
 * `--report` still works for these: it writes where the caller pointed, not into
 * the run.
 */
const READ_ONLY_COMMANDS = new Set(["dossier", "graph", "paths", "check", "tools", "help", "version"]);

/**
 * Run a command, archiving its output when asked.
 *
 * `--report <path>` writes this one command's transcript; a run directory gets an
 * appended JOURNAL.md entry unless `--no-journal`. Both are ADDITIVE — the tee'ing
 * sink still writes every line to the real streams, so stdout is byte-identical to
 * a run without either flag. With neither requested, `dispatch` runs untouched and
 * nothing is buffered.
 *
 * `mcp` is excluded: its stdout carries JSON-RPC frames and it never returns.
 */
async function withArchiving(args: ParsedArgs, argv: string[], execute: () => Promise<number>): Promise<number> {
  const reportPath = flagStr(args, "report");
  // `scan` names its run dir `--out`; every later stage calls it `--run`.
  const runDir = flagStr(args, "run") ?? flagStr(args, "out");
  const journal = runDir !== undefined && !READ_ONLY_COMMANDS.has(args._[0] ?? "") && !flagBool(args, "no-journal");
  if ((!reportPath && !journal) || args._[0] === "mcp") return execute();

  // Fail BEFORE running: writing a report is the point of passing the flag, and
  // discovering the extension is unusable after a ten-minute scan is useless.
  if (reportPath) {
    const ext = extname(reportPath).replace(/^\./, "").toLowerCase();
    if (!REPORT_FORMATS.includes(ext)) {
      eprintln(`ultrasec: ${new UnknownReportFormat(ext || "(none)").message}`);
      return 2;
    }
  }

  const { result, stdout, stderr } = await teeOutput(execute);
  const transcript: Transcript = { command: `ultrasec ${argv.join(" ")}`, stdout, stderr, code: result, at: new Date().toISOString() };

  if (reportPath) {
    try {
      writeReport(reportPath, transcript);
    } catch (e) {
      eprintln(`ultrasec: could not write --report ${reportPath}: ${(e as Error).message}`);
      return 2;
    }
  }
  // Best-effort: the journal records the audit, it never gates it.
  if (journal && runDir) {
    try {
      appendJournal(runDir, transcript);
    } catch {
      /* an unwritable run dir already surfaced through the command itself */
    }
  }
  return result;
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
