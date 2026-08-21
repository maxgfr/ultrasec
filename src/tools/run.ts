import { execFileSync, spawnSync } from "node:child_process";
import { join, relative } from "node:path";
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

function exec(name: string, args: string[], cwd: string, useStderr = false): { stdout: string; failed: boolean; err?: string } {
  const capture = { cwd, encoding: "utf8" as const, timeout: TIMEOUT_MS, maxBuffer: MAX_BUFFER };
  try {
    if (useStderr) {
      // Capture both; the diagnostics live on fd 2 for these tools.
      const res = spawnSync(name, args, { ...capture, stdio: ["ignore", "pipe", "pipe"] });
      if (res.error) return { stdout: "", failed: true, err: res.error.message };
      return { stdout: String(res.stderr ?? ""), failed: false };
    }
    const stdout = execFileSync(name, args, { ...capture, stdio: ["ignore", "pipe", "ignore"] });
    return { stdout, failed: false };
  } catch (e: unknown) {
    // execFileSync throws on non-zero exit — but scanners exit non-zero WHEN they
    // find issues, and still print JSON to stdout. Recover it.
    const err = e as { stdout?: Buffer | string; message?: string };
    const stdout = err.stdout ? err.stdout.toString() : "";
    if (stdout.trim()) return { stdout, failed: false };
    return { stdout: "", failed: true, err: err.message };
  }
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

/** Run one adapter natively if its binary (or `command` override) is present. Never throws. */
function runNative(adapter: ToolAdapter, repo: string, ctx: RunContext): ToolRunResult {
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

  const { stdout, failed, err } = exec(cmd[0]!, [...cmd.slice(1), ...argv], repo, adapter.stderr);
  return finish(adapter, repo, stdout, failed, err, false, ctx);
}

/**
 * Exec one adapter once per workspace directory and merge the results.
 *
 * Findings stay relative to the REPO (not the workspace), so a `web/` advisory
 * cites `web/pnpm-lock.yaml` and correlates with every other tool. The note
 * names each directory audited: a monorepo where only some workspaces were
 * covered must never read like a full pass.
 */
function runEachWorkspace(adapter: ToolAdapter, repo: string, cmd: string[], argv: string[], dirs: string[], ctx: RunContext): ToolRunResult {
  const findings: Finding[] = [];
  const covered: string[] = [];
  const failures: string[] = [];
  for (const dir of dirs) {
    const rel = relative(repo, dir);
    const { stdout, failed, err } = exec(cmd[0]!, [...cmd.slice(1), ...argv], dir, adapter.stderr);
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

/** Run one adapter via its official Docker image. Never throws. */
function runDocker(adapter: ToolAdapter, repo: string, ctx: RunContext): ToolRunResult {
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
  const { stdout, failed, err } = exec("docker", args, repo, adapter.stderr);
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

export function runAdapter(adapter: ToolAdapter, repo: string, useDocker = false, ctx: RunContext = {}): ToolRunResult {
  return useDocker ? runDocker(adapter, repo, ctx) : runNative(adapter, repo, ctx);
}

export interface OrchestrateResult {
  findings: Finding[];
  toolsRun: string[];
  results: ToolRunResult[];
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
}

/**
 * Run a set of adapters and merge their findings via cross-tool correlation
 * (`correlate`): the same issue reported by multiple scanners collapses into one
 * finding whose `sources` lists every producer. `which` selects adapters by
 * name; default = all. In docker mode only adapters with an official image run.
 * Missing tools are skipped gracefully (recorded, not fatal).
 */
export function orchestrate(adapters: ToolAdapter[], repo: string, opts: OrchestrateOptions = {}): OrchestrateResult {
  let selected = opts.which?.length ? adapters.filter((a) => opts.which!.includes(a.name)) : adapters;
  if (opts.useDocker) selected = selected.filter((a) => a.dockerImage);

  const ctx: RunContext = { offline: opts.offline, sbom: opts.sbom, pruned: opts.pruned };
  const results: ToolRunResult[] = [];
  const all: Finding[] = [];
  for (const a of selected) {
    const r = runAdapter(a, repo, opts.useDocker, ctx);
    results.push(r);
    all.push(...r.findings);
  }
  const findings = correlate(all);
  const toolsRun = results.filter((r) => r.ran && r.ok).map((r) => r.name);
  return { findings, toolsRun, results };
}
