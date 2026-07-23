import { execFileSync } from "node:child_process";
import type { Category, Finding, PathStep, CodeLoc } from "../types.js";
import { detect } from "./registry.js";
import { correlate } from "./correlate.js";

// Adapter contract: each scanner provides how to invoke it and how to parse its
// JSON into normalized Findings. The runner detects presence, runs the installed
// ones, and tolerates the non-zero exit codes scanners use to signal "findings
// found". With `useDocker`, a scanner that publishes an official image is run via
// `docker run` instead — zero local install — with the repo bind-mounted at /work.

/** Per-run knobs threaded from `orchestrate` down into adapter hooks. */
export interface RunContext {
  /** True under `scan --offline` — adapters with `network` are skipped. */
  offline?: boolean;
  /** Absolute path of a CycloneDX SBOM generated this run, if any. */
  sbom?: string;
}

export interface ToolAdapter {
  name: string;
  category: Category;
  /** Args after the binary; `target` is the repo path (native) or /work (docker). */
  argv(target: string, ctx?: RunContext): string[];
  /** Normalize raw stdout (JSON) into findings. Must not throw on empty input. */
  parse(raw: string, repo: string): Finding[];
  /**
   * Some tools (hadolint) scan explicit files, not a directory. When present,
   * the returned repo-relative paths are appended to argv (they resolve under
   * both the native cwd and the /work docker mount). An empty list ⇒ skip the
   * run with a "no target files" note (nothing to scan).
   */
  enumerate?(repo: string): string[];
  /** Some tools (govulncheck) stream NDJSON; default reads one JSON blob. */
  streaming?: boolean;
  /** Pinned official image enabling `--docker` mode (omitted ⇒ native-only). */
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
  /** Needs the network on every run (registry-query audits) → skipped under
   *  --offline. A function answers per-run ("only if feeds not cached"). */
  network?: boolean | (() => boolean);
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

function exec(name: string, args: string[], cwd: string): { stdout: string; failed: boolean; err?: string } {
  try {
    const stdout = execFileSync(name, args, {
      cwd,
      encoding: "utf8",
      timeout: TIMEOUT_MS,
      maxBuffer: MAX_BUFFER,
      stdio: ["ignore", "pipe", "ignore"],
    });
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
  const { stdout, failed, err } = exec(cmd[0]!, [...cmd.slice(1), ...argv], repo);
  return finish(adapter, repo, stdout, failed, err, false);
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
  const args = ["run", "--rm", "-v", `${repo}:${MOUNT}`, "-w", MOUNT, adapter.dockerImage, ...inner];
  const { stdout, failed, err } = exec("docker", args, repo);
  return finish(adapter, repo, stdout, failed, err, true);
}

function finish(adapter: ToolAdapter, repo: string, stdout: string, failed: boolean, err: string | undefined, docker: boolean): ToolRunResult {
  if (failed) return { name: adapter.name, ran: true, ok: false, findings: [], note: `run failed: ${err ?? "no output"}` };
  try {
    // Normalize paths to repo-relative: strip /work (docker) or the repo dir (native).
    const base = docker ? MOUNT : repo;
    const findings = relativizeFindings(adapter.parse(stdout, repo), base);
    return { name: adapter.name, ran: true, ok: true, findings, note: `${findings.length} finding(s)${docker ? " (docker)" : ""}` };
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
}

/**
 * Run a set of adapters and merge their findings via cross-tool correlation
 * (`correlate`): the same issue reported by multiple scanners collapses into one
 * finding whose `sources` lists every producer. `which` selects adapters by
 * name; default = all. In docker mode only adapters with an official image run.
 * Missing tools are skipped gracefully (recorded, not fatal).
 */
export function orchestrate(adapters: ToolAdapter[], repo: string, opts: OrchestrateOptions = {}): OrchestrateResult {
  let selected = opts.which && opts.which.length ? adapters.filter((a) => opts.which!.includes(a.name)) : adapters;
  if (opts.useDocker) selected = selected.filter((a) => a.dockerImage);

  const ctx: RunContext = { offline: opts.offline, sbom: opts.sbom };
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
