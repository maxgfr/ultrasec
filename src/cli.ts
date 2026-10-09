import { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { warmGrammars } from "./vendor/codeindex-engine.mjs";
import { VERSION } from "./types.js";
import { parseArgs, flagBool, flagStr, numFlag, println, eprintln, type ParsedArgs } from "./util.js";
import { releaseQuiet, setQuiet, teeOutput } from "./util.js";
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
  audit      ONE command, ONE report: scan (every scan flag passes through) →
             the stage pipeline → check → <run>/REPORT.md (REPORT.html with
             --html; both with --html --md) → remove the intermediates. Prints
             the report path and a one-line status: adjudicated & grounded, or
             DRAFT with why and a 'next:' line. Exit 0 once the report is
             written. ZERO agent calls unless --powered <cli> (drives
             that CLI per worklist; --cross-check <cli>) or --council
             "<reviewer:model,…>". --keep-work keeps .work/ and the JSON
             worklists for an agent to adjudicate (then render + clean).
             Re-running on the same --out merges (verdicts survive); --fresh
             starts over. --full: exhaustive annexes. --strict: exit 1 on a
             DRAFT. Flags: --repo · --out · --html · --md · --full ·
             --keep-work · --powered <cli> · --cross-check <cli> · --council ·
             --stages · --fresh · --strict · --json · scan flags.
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
             --secrets-history (gitleaks walks every commit; default scans a
             snapshot of the tracked files and reports history as not scanned) ·
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
  graph      Show the links into/out of a file or symbol. Reads <run>/.work/graph.json
             with --run, else live-scans --repo. Flags: <file|symbol> · --depth n
             (default 1) · --run · --repo · --json.
  paths      List candidate cross-file source→sink chains.
             --surface narrows to one half of the report: 'code' (this repo's
             own source), 'supply' (secrets + CI/IaC), 'deps' (advisories) or
             'all' (default). --min-severity <s> keeps <s> AND above (as on
             check); --severity <s> keeps exactly <s> and names what it hid
             above it. Flags: --run · --kind <k> · --min-severity <s> ·
             --severity <s> · --surface <s> · --json.
  dossier    Print the grounding packet for one finding (real code + neighbours).
             The id may be a unique PREFIX. CONTEXT.md is reprinted before each
             finding: --compact keeps only the hunt-list/exposure/criticality
             sections, --no-context drops it. The packet carries the WHOLE
             enclosing function at the source and the sink, plus 'Who can reach
             this' — the route file, the callers of the entry symbol, the auth
             and rate-limit markers in scope, the sanitizers near the path.
             --brief restores the compact windows for batch fan-out. A comma
             list (a,b,c) is a FAMILY: context and checklist once, the first
             member in full, then a line and a ±3-line window per member.
             Flags: <finding-id>[,<id>…] · --run · --repo · --compact ·
             --no-context · --brief.
  triage     Fast, code-free first pass over OPEN candidates: emit / apply
             noise|keep. 'noise' dismisses only low/med/info; on high/critical
             it is ignored (kept open for verify). --surface narrows the emitted
             worklist (code | supply | deps | code+supply | all); --apply never takes it, since
             a verdict file names its own ids.
             Flags: --run · --apply · --surface <s> · --json.
  verify     Emit / apply the adversarial finding↔evidence worklist. --shards n
             --shard i splits the emit across fan-out workers, writing
             VERIFY.todo.<i>.json (the .md brief always covers the FULL worklist).
             --apply takes a file, a comma-list, or a DIRECTORY (picks up every
             *verdict*.json, sorted) and fails closed if every fragment is stale.
             The worklist is a DELTA: findings an earlier pass already adjudicated
             as needs-human are withheld until --all. --apply reports any verdict
             that changes an already-adjudicated finding; under --strict that
             fails unless --re-verdict is passed. --surface (default code+supply)
             narrows the emitted worklist: dependency advisories are ranked per
             package in the report, not ruled one by one; --surface all restores
             them. --apply never takes it.
             Flags: --run · --shards · --shard · --apply · --surface <s> · --json.
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
             fragment is stale. --surface (default code+supply) narrows the
             emitted worklist; --surface all restores the advisories.
             Flags: --run · --repo · --apply · --surface <s> · --json.
  assumptions
             Build the assumption map BEFORE hunting: per unit, what it
             guarantees (cited) and what it depends on that nothing enforces.
             An assumption marked 'nothing-found' is a place the code trusts
             something nobody wrote down — the highest-value lead an audit
             produces, and one no taint walk can reach. --apply writes
             ASSUMPTIONS.md and hands the leads to the next 'investigate' emit.
             Flags: --run · --repo · --apply · --strict ·
             --scope/--include/--exclude/--max-files/--gitignore · --json.
  guards     Cross the two lists the engine already builds but never compares:
             every handler that reads request data, and the markers visible in
             its scope. This is the vulnerability that is an ABSENCE — a missing
             check has no line to taint-trace, so nothing else in the engine can
             reach it. --lens auth (default) looks for authentication/
             authorization; --lens throttle looks for rate limiting and flags the
             handlers that AUTHENTICATE, where the absence is credential stuffing
             + account enumeration rather than capacity. No marker of that kind
             anywhere in the tree is reported as ONE architectural fact, not one
             finding per handler. Rows with none are a worklist; a marker in
             scope is a CANDIDATE, never proof. --apply turns an 'unguarded' /
             'unthrottled' verdict into a cited finding (GUARDS.md / THROTTLE.md).
             The project's own helpers (assertServerSession, tokens.require…)
             are declared once in CONTEXT.md — 'Auth markers: a, b.c' /
             'Throttle markers: …' — or ad hoc with --marker.
             Flags: --run · --repo · --lens auth|throttle · --marker <name>[,…] ·
             --apply · --strict · --json.
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
  render     Write THE report: <run>/REPORT.md (or REPORT.html with --html;
             both with --html --md) — executive summary, dashboard, chains,
             follow-up, findings by severity then area (scenario · fix ·
             effort · priority), secrets, CI/CD, dependencies one row per
             package, hardening, coverage, remediation plan, annexes.
             Dismissals are SUMMARISED and repeated findings are one card;
             --full restores every exhaustive table. Folds <run>/NARRATIVE.json
             (or --narrative <file>), grounding-checked. A HIGH/CRITICAL
             source-code candidate never read makes it a DRAFT (a banner says
             why); a written report exits 0 — --strict exits 1 on a DRAFT.
             --legacy writes the previous SUMMARY.md + tiered REPORT.md +
             index.html. Flags: --run · --html · --md · --full · --narrative
             <file> · --strict · --legacy.
  coverage   The honest complement to 'only report what you can exploit': a
             standards matrix of what this audit looked at and what it did NOT.
             A short report reads as "nothing there" when it means "nothing
             there, in what I looked at" — this separates the two, and names the
             categories no deterministic signal can cover so you answer them
             explicitly. --standard scores against ASVS (default), the OWASP
             Top 10, the OWASP API Top 10, MASVS or the CWE Top 25. Also the
             weakness-class × framework matrix: matched by a pack, degraded
             (no pack, version outside testedWith), AI-hunted, or not covered.
             Read-only; prints the counts — --full prints the matrix.
             Flags: --run ·
             --standard asvs|owasp-top10|owasp-api-top10|masvs|cwe-top25 ·
             --full · --write (COVERAGE.md) · --json (--classes: the class matrix).
  check      Gate: every finding must cite resolvable [file:line] (anti-hallucination).
             READ-ONLY — it writes nothing and changes no status; --semantic ALSO
             fails when a HIGH/CRITICAL candidate outside the dependency surface
             is still unadjudicated (the predicate render's DRAFT banner uses);
             open advisories are reported, never failing. Exit 0 ok · 1 gate
             failed · 2 unreadable run. Flags: --run · --repo · --semantic ·
             --min-severity critical|high|medium|low|info · --json.
  clean      Remove the intermediates — .work/, worklists, DOSSIER.md,
             orchestration and council scratch — KEEPING REPORT.md/REPORT.html,
             findings.json, manifest.json, CONTEXT.md and NARRATIVE.json (and an
             older run's top-level JOURNAL.md); --all wipes the
             whole run dir, --keep-output keeps everything. With --docker also
             removes the scanner images + toolbox image + trivy cache volume
             (--dry-run to preview). A run that was never scanned is removed whole.
             Flags: --run · --all · --keep-output · --docker · --dry-run · --json.
  run        Orchestrate the AI stages (context → assumptions → triage → guards →
             throttle → investigate → verify → revalidate → variants → narrative →
             implement), then ALWAYS check + the report (as render). DEFAULT
             makes ZERO external calls: scans + emits every worklist + prints the agent
             TODO. --powered drives an agent CLI per worklist (keys live in that CLI,
             not ultrasec); --cross-check <cli> escalates high/critical verify/
             revalidate disagreement to needs-human. --stages selects a subset of the
             stage names above — 'check'/'render' are unconditional post-steps
             and are NOT valid --stages tokens. Worklists are JSON only (--md
             adds the human .md twins). Flags: --repo · --out · --powered ·
             --agent <name|tpl> · --cross-check <name|tpl> · --stages · --no-scan ·
             --scope/--include/--exclude/--max-files/--gitignore · --json.
  council    A second opinion from OTHER model families, through their own
             agent CLIs. Reviewers are data: built-in presets for common agent
             CLIs, or entries in --reviewer-config <file.json> (default
             $XDG_CONFIG_HOME/ultrasec/council.json; never read from the audited
             repo). Each reviewer works on a \`git archive HEAD\` snapshot under
             <run>/council/, started with an emptied environment and a short
             argv pointing at a brief file; reviewers run in parallel, their
             reports are parsed into claims, every path:line is resolved against
             the snapshot, and claims are grouped across reviewers into
             candidates (corroboration is a prior, never a verdict). A reviewer
             cut by budget/timeout/quota is resumed for ONE closing turn.
             Without --models: prints the plan, ZERO calls. --apply folds the
             orchestrator's accept/reject decisions through the investigate
             citation gate; contested findings stay a worklist.
             Flags: --run · --repo · --phase blind|devil · --models
             "<reviewer>:<model>,…" · --focus "name=area;…" · --fallback
             "<reviewer>:<model>,…" · --timeout-min (default 60) · --max-cost
             <usd> · --lang en|fr · --reviewer-config <file.json> ·
             --placeholder-pattern <regex> (repeatable) · --parse · --resume
             <reviewer> · --apply <file> · --strict · --json.
  orchestrate Emit the run's multi-agent orchestration from its CURRENT worklists
             into <run>/.work/orchestration/: one <phase>.workflow.mjs per ready phase
             (adjudicate | verify | revalidate | investigate; families kept
             whole, at most 12 agents, the items baked into each prompt as
             compact JSON lines), the dispatch contracts (agents/<role>.md) and a sequential
             RUNBOOK.md fallback. Subagents RETURN verdict/discovery fragments;
             every conservative --apply fold stays with you (one writer).
             --surface narrows the fan-out to code | supply | deps | code+supply
             | all (default code+supply) — a fan-out over every open dependency
             advisory pays for a dossier read that a ranked list already answers.
             Flags: --run · --phase <name> · --surface <s> · --eco (runbook +
             contracts only) · --list (phase status as JSON).
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
  --require-tools <a,b>  scan: require these scanners to execute successfully.
                        On a full scan it adds the obligation to --tools auto
                        (every installed scanner still runs); on a scoped or
                        --diff scan without --tools it selects them.
                        Skipped/failed/missing outcome exits 1; artifacts are kept.
  --help, -h     Show this help.
  --version, -v  Print the version.
  --json         Machine-readable output (every command above except render, dossier
                 and mcp). An emitting stage prints {todo, items, counts}, not the
                 worklist it just wrote.
  --quiet        Hold stderr (progress, notes) back; it is printed only if the
                 command fails. stdout is unchanged.
  --report <p>   ALSO archive this command's output to <p>; the extension picks the
                 format (.md, .html, .json, .txt/.log). stdout is unchanged; an
                 unknown extension exits 2 before the command runs.
  --no-journal   Don't append this command to <run>/.work/JOURNAL.md (the
                 append-only record of every command run against an audit dir).
  --md           Also write each worklist's human .md brief (or ULTRASEC_MD=1);
                 by default worklists are JSON only and the instructions print.
  --strict       On an --apply stage, exit 1 if any row was refused, so a partial
                 fold can't pass CI. (triage/verify/investigate/revalidate)

  --apply -      Read the payload from stdin instead of a path.

EXIT CODES
  0  ok        1  a gate failed (check) / nothing usable ingested (import)
                  / rows refused under --strict / required scanner incomplete
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
const SCANNING_COMMANDS = new Set(["audit", "scan", "run", "graph", "map", "context", "investigate", "logs"]);

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

  // `--quiet` holds stderr back for every command (scan also mutes its own
  // progress stream with it); a failing command still prints what it held.
  setQuiet(flagBool(args, "quiet"));
  const code = await withArchiving(args, argv, () => dispatch(args._[0], args));
  releaseQuiet(code !== 0);
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
 * Commands whose last act is to remove `.work/`: `clean`, and `audit` without
 * `--keep-work`. Journaling them would recreate `.work/JOURNAL.md` the moment
 * after it was removed — one stray folder in a run that promised to hold only
 * the report.
 */
function leavesOnlyDeliverables(args: ParsedArgs): boolean {
  const cmd = args._[0];
  return cmd === "clean" || (cmd === "audit" && !flagBool(args, "keep-work"));
}

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
  const journal = runDir !== undefined && !READ_ONLY_COMMANDS.has(args._[0] ?? "") && !flagBool(args, "no-journal") && !leavesOnlyDeliverables(args);
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
