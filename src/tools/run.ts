import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { relative } from "node:path";
import type { Category, Finding, PathStep, CodeLoc } from "../types.js";
import { detect } from "./registry.js";
import { correlate } from "./correlate.js";

// Adapter contract: each scanner provides how to invoke it and how to parse its
// JSON into normalized Findings. The runner detects presence, runs the installed
// ones, and tolerates the non-zero exit codes scanners use to signal "findings
// found". With `useDocker`, a scanner that publishes an official image is run via
// `docker run` instead — zero local install — with the repo bind-mounted at /work.
// Images track each tool's rolling `latest` tag (see each adapter's `dockerImage`)
// rather than a pinned version, so `--pull always` is forced on every docker run —
// without it a previously cached `latest` would silently keep being reused and the
// "latest" tag would become cosmetic.

/** Per-run knobs threaded from `orchestrate` down into adapter hooks. */
export interface RunContext {
  /** True under `scan --offline` — adapters with `network` are skipped. */
  offline?: boolean;
  /** Absolute path of a CycloneDX SBOM generated this run, if any. */
  sbom?: string;
  /**
   * Repo-relative directory this invocation is auditing, for a tool whose
   * manifest can live below the root (see `ToolAdapter.workspaces`). Empty/absent
   * ⇒ the repo root.
   *
   * An adapter that names a file itself (the lockfile audits) MUST prefix it with
   * this, because the finding id is derived from that path inside
   * `makeToolFinding`. Re-anchoring after the fact would leave the id keyed on the
   * workspace-relative path — so two workspaces carrying the same advisory collide
   * on one id, and every citation points at a file the repo root doesn't have.
   */
  workspace?: string;
  /**
   * "The walk would have pruned this path." External scanners get the RAW repo
   * bind-mounted (`docker run -v <repo>:/work`) and have never seen
   * `--gitignore`/`--exclude`, so a scan that pruned 1.1 GB of vendored data
   * from its own walk still shipped 51 findings out of it. Applied to results
   * rather than to argv because no adapter takes an exclude argument and only
   * one uses the explicit-file seam — result-side filtering is total and costs
   * one call.
   *
   * Absent ⇒ nothing is pruned, byte-identical to before this field existed.
   */
  pruned?: (rel: string) => boolean;
  /**
   * Result cache for `cacheable` adapters (`scan --resume`). Absent ⇒ every
   * adapter runs, as before.
   */
  cache?: ToolResultCache;
}

/** One cached scanner result, keyed on everything that could change its output. */
export interface ToolCacheEntry {
  key: string;
  result: ToolRunResult;
}

/**
 * What `--resume` remembers about the external scanners.
 *
 * Only an adapter that declares `cacheable` is ever served from here, and only
 * when its key matches: the adapter name, the detected version, the exact
 * argv, the repository's HEAD (for a history scanner), the walk digest (every
 * file's path, size and mtime) and the caller's salt (the prune flags). A
 * scanner whose output depends on anything else — a vulnerability database
 * that refreshes, a rule set pulled from the network — must not be cacheable.
 */
export interface ToolResultCache {
  entries: Map<string, ToolCacheEntry>;
  /** `sha256(rel\0size\0mtimeMs\n …)` over the run's walk. */
  treeDigest: string;
  /** `git rev-parse HEAD`, when the repo is a git checkout. */
  head?: string;
  /** Anything else that shapes a result — the prune flags, for one. */
  salt?: string;
}

export interface ToolAdapter {
  name: string;
  category: Category;
  /** Args after the binary; `target` is the repo path (native) or /work (docker). */
  argv(target: string, ctx?: RunContext): string[];
  /** Normalize raw stdout (JSON) into findings. Must not throw on empty input.
   *  `ctx.workspace` names the sub-directory being audited, when there is one. */
  parse(raw: string, repo: string, ctx?: RunContext): Finding[];
  /**
   * Some tools (hadolint) scan explicit files, not a directory. When present,
   * the returned repo-relative paths are appended to argv (they resolve under
   * both the native cwd and the /work docker mount). An empty list ⇒ skip the
   * run with a "no target files" note (nothing to scan).
   */
  enumerate?(repo: string): string[];
  /** Some tools (govulncheck) stream NDJSON; default reads one JSON blob. */
  streaming?: boolean;
  /** Official image (rolling `latest` tag) enabling `--docker` mode (omitted ⇒ native-only). */
  dockerImage?: string;
  /** False when the image's ENTRYPOINT is NOT the tool (e.g. semgrep). Default true. */
  dockerEntrypointIsTool?: boolean;
  /** Override the executable (argv0 prefix): e.g. ["bash", "/abs/script.sh"],
   *  ["yarn", "npm"]. Return null when the host can't run it → graceful
   *  "not installed" skip. When present this REPLACES the PATH probe of `name`. */
  command?(): string[] | null;
  /** Repo-content gate: null = run; a string = skip note (e.g. "no package-lock.json").
   *  Unlike `enumerate`, the result is NOT appended to argv. */
  applicable?(repo: string): string | null;
  /**
   * Directories this tool should be run in, when its manifest can live below the
   * repo root (monorepos). Returns absolute paths, nearest-first; the runner
   * execs once per directory and merges the findings, naming each in the note.
   * Absent ⇒ one run at the repo root, as before.
   */
  workspaces?(repo: string): string[];
  /** Needs the network on every run (registry-query audits) → skipped under
   *  --offline. A function answers per-run ("only if feeds not cached"). */
  network?: boolean | (() => boolean);
  /**
   * Read diagnostics from STDERR instead of stdout. cppcheck (and several other
   * C/C++ tools) write their report there by convention and keep stdout for
   * progress, so ignoring stderr means parsing an empty string and reporting a
   * clean run — a silent false negative, which is the one failure mode this belt
   * must not have.
   */
  stderr?: boolean;
  /**
   * The result is a pure function of the tree, the tool version and the argv,
   * so `--resume` may replay it when none of those changed. Claim it ONLY for
   * a scanner with no external state: bandit, gosec, checkov, hadolint,
   * cppcheck, kingfisher, gitleaks (keyed on HEAD too). Trivy/osv/grype/
   * govulncheck/cargo-audit consult a database that refreshes and semgrep
   * pulls rules, so `!network` would be the wrong test — they stay uncached.
   */
  cacheable?: boolean;
}

export interface ToolRunResult {
  name: string;
  ran: boolean;
  ok: boolean;
  findings: Finding[];
  note: string;
}

/** Per-tool outcome, persisted so a report distinguishes "ran, 0 findings" from
 *  "skipped (not installed / no target)". */
export interface ToolStatus {
  name: string;
  status: "ran" | "empty" | "skipped" | "failed";
  findings?: number;
  note?: string;
}

/** Collapse the rich run results into a persisted per-tool status. */
export function toolStatus(results: ToolRunResult[]): ToolStatus[] {
  return results.map((r) => {
    if (!r.ran) return { name: r.name, status: "skipped", ...(r.note ? { note: r.note } : {}) };
    if (!r.ok) return { name: r.name, status: "failed", ...(r.note ? { note: r.note } : {}) };
    const status = r.findings.length ? "ran" : "empty";
    return { name: r.name, status, findings: r.findings.length, ...(r.note ? { note: r.note } : {}) };
  });
}

// Exported for reuse by other execFileSync callers outside the adapter runner
// (e.g. src/tools/sbom.ts's syft invocation) that want the same bounds.
export const TIMEOUT_MS = 300_000;
export const MAX_BUFFER = 64 * 1024 * 1024;
const MOUNT = "/work";

interface ExecResult {
  stdout: string;
  failed: boolean;
  err?: string;
}

/**
 * Spawn one scanner and collect its output. Asynchronous, so several scanners
 * can run at once (see `orchestrate`); the semantics are exactly the old
 * synchronous ones:
 *
 * - stderr is PIPED, not ignored: on the happy path it is discarded either way,
 *   but when the tool fails it holds the only thing that tells a user what to
 *   do. Without it `gosec` and `hadolint` failing on a real repo reported
 *   "Command failed: docker run --rm --pull always -v …" and nothing else.
 * - a non-zero exit is NOT a failure when stdout carries a report: scanners
 *   exit non-zero WHEN they find issues, and still print JSON.
 * - `useStderr` returns fd 2 as the report (cppcheck writes there by convention).
 */
function execAsync(name: string, args: string[], cwd: string, useStderr = false): Promise<ExecResult> {
  return new Promise((resolve) => {
    execFile(name, args, { cwd, encoding: "utf8", timeout: TIMEOUT_MS, maxBuffer: MAX_BUFFER, windowsHide: true }, (error, stdout, stderr) => {
      const out = String(stdout ?? "");
      const errText = String(stderr ?? "");
      if (useStderr) {
        // The report lives on fd 2, whatever the exit code. Only a failure to
        // run at all (ENOENT/EACCES — a string code — or a timeout, no code)
        // is a failure.
        const code = (error as { code?: unknown } | null)?.code;
        if (error && typeof code !== "number") return resolve({ stdout: "", failed: true, err: error.message });
        return resolve({ stdout: errText, failed: false });
      }
      if (!error) return resolve({ stdout: out, failed: false });
      if (out.trim()) return resolve({ stdout: out, failed: false });
      resolve({ stdout: "", failed: true, err: withDiagnostic(error.message, errText) });
    });
  });
}

/** Longest single stderr line kept in a failure note. */
const DIAG_MAX = 300;

/**
 * Attach the tool's own diagnostic to the generic "Command failed" message.
 *
 * Takes the LAST non-empty stderr line: scanners print progress and warnings
 * first and the reason they gave up last, so the tail is the actionable part.
 */
function withDiagnostic(message: string | undefined, stderr: Buffer | string | undefined): string {
  const base = message ?? "no output";
  const lines = String(stderr ?? "")
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);
  const last = lines[lines.length - 1];
  if (!last) return base;
  const diag = last.length > DIAG_MAX ? `${last.slice(0, DIAG_MAX)}…` : last;
  return `${base} — ${diag}`;
}

/**
 * Rewrite a location's file to repo-relative by stripping a leading base dir.
 * `base` is the repo path (native runs) or the /work mount (docker runs). Tools
 * variously emit absolute (`/work/x`, `/home/me/proj/x`) or already-relative
 * paths; this normalizes them all so findings are consistent and the report is
 * clean. Paths outside `base` (e.g. a dependency in the module cache) are left
 * as-is (they're external references, handled by the grounding gate).
 */
function relLoc<T extends CodeLoc>(loc: T, base: string): T {
  if (base && loc.file.startsWith(base + "/")) return { ...loc, file: loc.file.slice(base.length + 1) };
  if (base && loc.file === base) return { ...loc, file: "." };
  return loc;
}
export function relativizeFindings(findings: Finding[], base: string): Finding[] {
  return findings.map((f) => ({
    ...f,
    source: f.source ? relLoc(f.source, base) : f.source,
    sink: f.sink ? relLoc(f.sink, base) : f.sink,
    path: f.path ? (f.path.map((p) => relLoc(p, base)) as PathStep[]) : f.path,
  }));
}

/**
 * Drop findings whose cited location the walk would have pruned. Runs right
 * after `relativizeFindings`, the one point every external-tool finding passes
 * through with repo-relative paths, native and docker alike.
 *
 * A finding is judged on the location it CITES (`sink`, else `source`). A
 * finding with no location at all — a dependency advisory keyed on a package
 * rather than a file — is never pruned: there is no path to test, and silently
 * losing a CVE because a path filter had nothing to say about it would be a far
 * worse bug than the one being fixed.
 */
export function prunePaths(findings: Finding[], pruned: (rel: string) => boolean): { findings: Finding[]; dropped: number } {
  const kept = findings.filter((f) => {
    const at = f.sink?.file ?? f.source?.file;
    return !at || !pruned(at);
  });
  return { findings: kept, dropped: findings.length - kept.length };
}

/**
 * Build the args for an adapter, appending enumerated file targets when the
 * adapter scans explicit files. Returns null when enumeration yields nothing
 * (the runner then records a graceful "no target files" skip).
 */
function buildArgv(adapter: ToolAdapter, repo: string, target: string, ctx: RunContext): string[] | null {
  const base = adapter.argv(target, ctx);
  if (!adapter.enumerate) return base;
  const files = adapter.enumerate(repo);
  if (!files.length) return null;
  return [...base, ...files];
}

/** True when `ctx.offline` and the adapter declares it needs the network this run. */
function blockedOffline(adapter: ToolAdapter, ctx: RunContext): boolean {
  if (!ctx.offline) return false;
  return typeof adapter.network === "function" ? adapter.network() : adapter.network === true;
}

/** The suffix a replayed result carries in its note, so `toolStatus` says so. */
export const CACHED_NOTE = "cached (--resume)";

/** The cache key for one native run — see `ToolResultCache` for what goes in. */
function cacheKey(adapter: ToolAdapter, cmd: string[], argv: string[], cache: ToolResultCache): string {
  const version = adapter.command ? cmd.join(" ") : (detect(adapter.name).version ?? "");
  const parts = [adapter.name, version, cmd.join("\0"), argv.join("\0"), cache.head ?? "", cache.treeDigest, cache.salt ?? ""];
  return createHash("sha256").update(parts.join("\n")).digest("hex");
}

/** Run one adapter natively if its binary (or `command` override) is present. Never throws. */
async function runNative(adapter: ToolAdapter, repo: string, ctx: RunContext): Promise<ToolRunResult> {
  if (blockedOffline(adapter, ctx)) {
    return { name: adapter.name, ran: false, ok: false, findings: [], note: "offline (network required)" };
  }
  let cmd: string[] | null;
  if (adapter.command) {
    cmd = adapter.command();
    if (!cmd) return { name: adapter.name, ran: false, ok: false, findings: [], note: "not installed" };
  } else {
    if (!detect(adapter.name).installed) {
      return { name: adapter.name, ran: false, ok: false, findings: [], note: "not installed" };
    }
    cmd = [adapter.name];
  }
  const applicableNote = adapter.applicable?.(repo);
  if (applicableNote) return { name: adapter.name, ran: false, ok: false, findings: [], note: applicableNote };
  const argv = buildArgv(adapter, repo, repo, ctx);
  if (!argv) return { name: adapter.name, ran: false, ok: false, findings: [], note: "no target files" };

  // A tool whose manifest can live below the root (the package-manager audits)
  // runs once per workspace — INCLUDING the single-workspace case, which is where
  // a repo like `web/pnpm-lock.yaml` lives and where getting the prefix wrong
  // produces findings citing a path the repo doesn't have.
  const dirs = adapter.workspaces?.(repo) ?? [];
  if (dirs.length) return runEachWorkspace(adapter, repo, cmd, argv, dirs, ctx);

  // Replay a previous run when nothing that could change its output has.
  const cache = adapter.cacheable ? ctx.cache : undefined;
  const key = cache ? cacheKey(adapter, cmd, argv, cache) : undefined;
  if (cache && key) {
    const hit = cache.entries.get(adapter.name);
    if (hit && hit.key === key) return { ...hit.result, findings: [...hit.result.findings], note: `${hit.result.note} · ${CACHED_NOTE}` };
  }

  const { stdout, failed, err } = await execAsync(cmd[0]!, [...cmd.slice(1), ...argv], repo, adapter.stderr);
  const result = finish(adapter, repo, stdout, failed, err, false, ctx);
  // Only a run that actually produced a report is worth replaying: a failure
  // is re-attempted next time, and "0 findings" from a crash never becomes
  // "0 findings" from a scan.
  if (cache && key && result.ran && result.ok) cache.entries.set(adapter.name, { key, result });
  return result;
}

/**
 * Exec one adapter once per workspace directory and merge the results.
 *
 * Findings stay relative to the REPO (not the workspace), so a `web/` advisory
 * cites `web/pnpm-lock.yaml` and correlates with every other tool. The note
 * names each directory audited: a monorepo where only some workspaces were
 * covered must never read like a full pass.
 */
async function runEachWorkspace(adapter: ToolAdapter, repo: string, cmd: string[], argv: string[], dirs: string[], ctx: RunContext): Promise<ToolRunResult> {
  const findings: Finding[] = [];
  const covered: string[] = [];
  const failures: string[] = [];
  for (const dir of dirs) {
    const rel = relative(repo, dir);
    const { stdout, failed, err } = await execAsync(cmd[0]!, [...cmd.slice(1), ...argv], dir, adapter.stderr);
    // Relativize against the REPO, and tell the adapter which workspace it is in,
    // so the path it records — and therefore the finding id — is repo-relative
    // from the start.
    const one = finish(adapter, repo, stdout, failed, err, false, { ...ctx, workspace: rel });
    if (!one.ok) {
      failures.push(`${rel || "."}: ${one.note}`);
      continue;
    }
    findings.push(...one.findings);
    covered.push(rel || ".");
  }
  const note = [
    `${findings.length} finding(s) across ${covered.length} workspace(s): ${covered.join(", ") || "none"}`,
    ...failures.map((f) => `failed ${f}`),
  ].join(" · ");
  return { name: adapter.name, ran: covered.length > 0, ok: covered.length > 0, findings, note };
}

/** Run one adapter via its official Docker image. Never throws. Never cached:
 *  the image is a rolling `latest`, so the same argv can mean a different tool. */
async function runDocker(adapter: ToolAdapter, repo: string, ctx: RunContext): Promise<ToolRunResult> {
  if (blockedOffline(adapter, ctx)) {
    return { name: adapter.name, ran: false, ok: false, findings: [], note: "offline (network required)" };
  }
  if (!adapter.dockerImage) return { name: adapter.name, ran: false, ok: false, findings: [], note: "no docker image" };
  const applicableNote = adapter.applicable?.(repo);
  if (applicableNote) return { name: adapter.name, ran: false, ok: false, findings: [], note: applicableNote };
  const argv = buildArgv(adapter, repo, MOUNT, ctx);
  if (!argv) return { name: adapter.name, ran: false, ok: false, findings: [], note: "no target files" };
  const inner = (adapter.dockerEntrypointIsTool === false ? [adapter.name] : []).concat(argv);
  const args = ["run", "--rm", "--pull", "always", "-v", `${repo}:${MOUNT}`, "-w", MOUNT, adapter.dockerImage, ...inner];
  const { stdout, failed, err } = await execAsync("docker", args, repo, adapter.stderr);
  return finish(adapter, repo, stdout, failed, err, true, ctx);
}

function finish(
  adapter: ToolAdapter,
  repo: string,
  stdout: string,
  failed: boolean,
  err: string | undefined,
  docker: boolean,
  ctx?: RunContext,
): ToolRunResult {
  if (failed) return { name: adapter.name, ran: true, ok: false, findings: [], note: `run failed: ${err ?? "no output"}` };
  try {
    // Normalize paths to repo-relative: strip /work (docker) or the repo dir (native).
    const base = docker ? MOUNT : repo;
    const relativized = relativizeFindings(adapter.parse(stdout, repo, ctx), base);
    // …then apply the SAME prune the walk applied, so `--gitignore` means one
    // thing across the whole run. The count is reported, not swallowed: the
    // status note has to describe what shipped, or a filtered run reads as a
    // quiet one.
    const { findings, dropped } = ctx?.pruned ? prunePaths(relativized, ctx.pruned) : { findings: relativized, dropped: 0 };
    const note = `${findings.length} finding(s)${docker ? " (docker)" : ""}${dropped ? ` · ${dropped} pruned (ignored paths)` : ""}`;
    return { name: adapter.name, ran: true, ok: true, findings, note };
  } catch (e) {
    return { name: adapter.name, ran: true, ok: false, findings: [], note: `parse failed: ${(e as Error).message}` };
  }
}

export function runAdapter(adapter: ToolAdapter, repo: string, useDocker = false, ctx: RunContext = {}): Promise<ToolRunResult> {
  return useDocker ? runDocker(adapter, repo, ctx) : runNative(adapter, repo, ctx);
}

export interface OrchestrateResult {
  findings: Finding[];
  toolsRun: string[];
  results: ToolRunResult[];
}

/**
 * One adapter's lifecycle, reported as it happens. Emitted twice per adapter —
 * once with no `result` when it starts, once with one when it finishes.
 *
 * A callback rather than a print, so `src/tools/` stays free of the output sink
 * (nothing in here imports `util.ts`, and the MCP server's stdout carries
 * JSON-RPC frames that a stray line would corrupt). The caller decides where it
 * goes.
 */
export interface ToolProgress {
  tool: string;
  /** 1-based position in this run's adapter list. */
  index: number;
  total: number;
  /** Present on completion only. */
  result?: ToolRunResult;
  /** Wall-clock milliseconds the adapter took. Completion only. */
  ms?: number;
}

export interface OrchestrateOptions {
  which?: string[];
  useDocker?: boolean;
  /** True under `scan --offline` — forwarded into the per-run RunContext. */
  offline?: boolean;
  /** Absolute path of a CycloneDX SBOM generated this run, if any. */
  sbom?: string;
  /** "The walk pruned this path" — forwarded into the per-run RunContext so a
   *  scanner's results honour `--gitignore`/`--exclude` like the walk does. */
  pruned?: (rel: string) => boolean;
  /** Called as each adapter starts and finishes — in the order they happen,
   *  which with `concurrency` > 1 is not the adapter order. One adapter can take
   *  twenty minutes walking git history, so without this a scan is
   *  indistinguishable from a hang. */
  onProgress?: (e: ToolProgress) => void;
  /** How many adapters run at once (default 4). `1` reproduces the old serial run. */
  concurrency?: number;
  /** Result cache for `cacheable` adapters (`scan --resume`). */
  cache?: ToolResultCache;
}

/** How many scanners run at once when the caller does not say. */
export const DEFAULT_TOOL_CONCURRENCY = 4;

/**
 * Run a set of adapters and merge their findings via cross-tool correlation
 * (`correlate`): the same issue reported by multiple scanners collapses into one
 * finding whose `sources` lists every producer. `which` selects adapters by
 * name; default = all. In docker mode only adapters with an official image run.
 * Missing tools are skipped gracefully (recorded, not fatal).
 *
 * Adapters run in a small pool (`concurrency`, default 4): each scanner is its
 * own process, most are I/O- and CPU-bound elsewhere, and 21 of them at up to
 * five minutes each in series was the whole wall-clock of a scan. The OUTPUT is
 * still deterministic: `results` is filled by index, so the merged finding list
 * is the same whatever order the processes finished in.
 */
export async function orchestrate(adapters: ToolAdapter[], repo: string, opts: OrchestrateOptions = {}): Promise<OrchestrateResult> {
  let selected = opts.which?.length ? adapters.filter((a) => opts.which!.includes(a.name)) : adapters;
  if (opts.useDocker) selected = selected.filter((a) => a.dockerImage);

  const ctx: RunContext = { offline: opts.offline, sbom: opts.sbom, pruned: opts.pruned, ...(opts.cache ? { cache: opts.cache } : {}) };
  const total = selected.length;
  const results: ToolRunResult[] = new Array(total);
  const concurrency = Math.max(1, Math.floor(opts.concurrency ?? DEFAULT_TOOL_CONCURRENCY));

  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < total) {
      const i = next++;
      const a = selected[i]!;
      opts.onProgress?.({ tool: a.name, index: i + 1, total });
      const started = Date.now();
      const r = await runAdapter(a, repo, opts.useDocker, ctx);
      results[i] = r;
      opts.onProgress?.({ tool: a.name, index: i + 1, total, result: r, ms: Date.now() - started });
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, total) }, worker));

  const all: Finding[] = [];
  for (const r of results) all.push(...r.findings);
  const findings = correlate(all);
  const toolsRun = results.filter((r) => r.ran && r.ok).map((r) => r.name);
  return { findings, toolsRun, results };
}
