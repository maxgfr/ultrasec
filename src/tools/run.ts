import { execFileSync } from "node:child_process";
import type { Category, Finding, PathStep, CodeLoc } from "../types.js";
import { detect } from "./registry.js";
import { byStr } from "../util.js";

// Adapter contract: each scanner provides how to invoke it and how to parse its
// JSON into normalized Findings. The runner detects presence, runs the installed
// ones, and tolerates the non-zero exit codes scanners use to signal "findings
// found". With `useDocker`, a scanner that publishes an official image is run via
// `docker run` instead — zero local install — with the repo bind-mounted at /work.

export interface ToolAdapter {
  name: string;
  category: Category;
  /** Args after the binary; `target` is the repo path (native) or /work (docker). */
  argv(target: string): string[];
  /** Normalize raw stdout (JSON) into findings. Must not throw on empty input. */
  parse(raw: string, repo: string): Finding[];
  /** Some tools (govulncheck) stream NDJSON; default reads one JSON blob. */
  streaming?: boolean;
  /** Pinned official image enabling `--docker` mode (omitted ⇒ native-only). */
  dockerImage?: string;
  /** False when the image's ENTRYPOINT is NOT the tool (e.g. semgrep). Default true. */
  dockerEntrypointIsTool?: boolean;
}

export interface ToolRunResult {
  name: string;
  ran: boolean;
  ok: boolean;
  findings: Finding[];
  note: string;
}

const TIMEOUT_MS = 300_000;
const MAX_BUFFER = 64 * 1024 * 1024;
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

/** Run one adapter natively if its binary is present. Never throws. */
function runNative(adapter: ToolAdapter, repo: string): ToolRunResult {
  if (!detect(adapter.name).installed) {
    return { name: adapter.name, ran: false, ok: false, findings: [], note: "not installed" };
  }
  const { stdout, failed, err } = exec(adapter.name, adapter.argv(repo), repo);
  return finish(adapter, repo, stdout, failed, err, false);
}

/** Run one adapter via its official Docker image. Never throws. */
function runDocker(adapter: ToolAdapter, repo: string): ToolRunResult {
  if (!adapter.dockerImage) return { name: adapter.name, ran: false, ok: false, findings: [], note: "no docker image" };
  const inner = (adapter.dockerEntrypointIsTool === false ? [adapter.name] : []).concat(adapter.argv(MOUNT));
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

export function runAdapter(adapter: ToolAdapter, repo: string, useDocker = false): ToolRunResult {
  return useDocker ? runDocker(adapter, repo) : runNative(adapter, repo);
}

export interface OrchestrateResult {
  findings: Finding[];
  toolsRun: string[];
  results: ToolRunResult[];
}

export interface OrchestrateOptions {
  which?: string[];
  useDocker?: boolean;
}

/**
 * Run a set of adapters and merge their findings, de-duplicated by id. `which`
 * selects adapters by name; default = all. In docker mode only adapters with an
 * official image run. Missing tools are skipped gracefully (recorded, not fatal).
 */
export function orchestrate(adapters: ToolAdapter[], repo: string, opts: OrchestrateOptions = {}): OrchestrateResult {
  let selected = opts.which && opts.which.length ? adapters.filter((a) => opts.which!.includes(a.name)) : adapters;
  if (opts.useDocker) selected = selected.filter((a) => a.dockerImage);

  const results: ToolRunResult[] = [];
  const merged = new Map<string, Finding>();
  for (const a of selected) {
    const r = runAdapter(a, repo, opts.useDocker);
    results.push(r);
    for (const f of r.findings) if (!merged.has(f.id)) merged.set(f.id, f);
  }
  const findings = [...merged.values()].sort((a, b) => byStr(a.id, b.id));
  const toolsRun = results.filter((r) => r.ran && r.ok).map((r) => r.name);
  return { findings, toolsRun, results };
}
