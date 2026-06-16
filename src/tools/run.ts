import { execFileSync } from "node:child_process";
import type { Category, Finding } from "../types.js";
import { detect } from "./registry.js";
import { byStr } from "../util.js";

// Adapter contract: each scanner provides how to invoke it and how to parse its
// JSON into normalized Findings. The runner detects presence, runs the installed
// ones, and tolerates the non-zero exit codes scanners use to signal "findings
// found" (trivy/gitleaks/semgrep/osv-scanner all exit non-zero on hits).

export interface ToolAdapter {
  name: string;
  category: Category;
  /** Args after the binary; `repo` is the absolute repo path. */
  argv(repo: string): string[];
  /** Normalize raw stdout (JSON) into findings. Must not throw on empty input. */
  parse(raw: string, repo: string): Finding[];
  /** Some tools (govulncheck) stream NDJSON; default reads one JSON blob. */
  streaming?: boolean;
}

export interface ToolRunResult {
  name: string;
  ran: boolean;
  ok: boolean;
  findings: Finding[];
  note: string;
}

const TIMEOUT_MS = 180_000;
const MAX_BUFFER = 64 * 1024 * 1024;

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
    const err = e as { stdout?: Buffer | string; status?: number; message?: string };
    const stdout = err.stdout ? err.stdout.toString() : "";
    if (stdout.trim()) return { stdout, failed: false };
    return { stdout: "", failed: true, err: err.message };
  }
}

/** Run one adapter if its binary is present. Never throws. */
export function runAdapter(adapter: ToolAdapter, repo: string): ToolRunResult {
  if (!detect(adapter.name).installed) {
    return { name: adapter.name, ran: false, ok: false, findings: [], note: "not installed" };
  }
  const { stdout, failed, err } = exec(adapter.name, adapter.argv(repo), repo);
  if (failed) return { name: adapter.name, ran: true, ok: false, findings: [], note: `run failed: ${err ?? "no output"}` };
  try {
    const findings = adapter.parse(stdout, repo);
    return { name: adapter.name, ran: true, ok: true, findings, note: `${findings.length} finding(s)` };
  } catch (e) {
    return { name: adapter.name, ran: true, ok: false, findings: [], note: `parse failed: ${(e as Error).message}` };
  }
}

export interface OrchestrateResult {
  findings: Finding[];
  toolsRun: string[];
  results: ToolRunResult[];
}

/**
 * Run a set of adapters and merge their findings, de-duplicated by id. `which`
 * selects adapters by name; default = all registered. Missing tools are skipped
 * gracefully (recorded in `results`, not fatal).
 */
export function orchestrate(adapters: ToolAdapter[], repo: string, which?: string[]): OrchestrateResult {
  const selected = which && which.length ? adapters.filter((a) => which.includes(a.name)) : adapters;
  const results: ToolRunResult[] = [];
  const merged = new Map<string, Finding>();
  for (const a of selected) {
    const r = runAdapter(a, repo);
    results.push(r);
    for (const f of r.findings) if (!merged.has(f.id)) merged.set(f.id, f);
  }
  const findings = [...merged.values()].sort((a, b) => byStr(a.id, b.id));
  const toolsRun = results.filter((r) => r.ran && r.ok).map((r) => r.name);
  return { findings, toolsRun, results };
}
