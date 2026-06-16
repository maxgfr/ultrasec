import type { Finding, Severity } from "../types.js";
import type { ToolAdapter } from "./run.js";
import { makeToolFinding, firstCwe } from "./normalize.js";

// Semgrep / OpenGrep → pattern + dataflow SAST. Identical JSON schema, so one
// parser serves both adapters. severity at extra.severity; cwe/refs under
// extra.metadata (rule-defined, may be absent).
const SEV: Record<string, Severity> = {
  ERROR: "high",
  WARNING: "medium",
  INFO: "low",
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
};

function parseSemgrep(tool: string, raw: string): Finding[] {
  const data = JSON.parse(raw || "{}") as any;
  const out: Finding[] = [];
  for (const r of data.results ?? []) {
    const md = r.extra?.metadata ?? {};
    if (r.extra?.sca_info) continue; // supply-chain matches aren't code SAST
    out.push(
      makeToolFinding({
        tool,
        category: "sast",
        ident: `${r.check_id}:${r.path}:${r.start?.line ?? ""}`,
        title: r.check_id,
        severity: SEV[String(r.extra?.severity ?? "").toUpperCase()] ?? "medium",
        message: r.extra?.message || r.check_id,
        file: r.path,
        line: r.start?.line,
        cwe: firstCwe(md.cwe),
        references: md.references ?? [],
      }),
    );
  }
  return out;
}

export const semgrep: ToolAdapter = {
  name: "semgrep",
  category: "sast",
  // The semgrep/semgrep image entrypoint is NOT `semgrep`, so the runner prepends it.
  dockerImage: "semgrep/semgrep:1.166.0",
  dockerEntrypointIsTool: false,
  argv: (target) => ["scan", "--json", "--quiet", "--config", "auto", target],
  parse: (raw) => parseSemgrep("semgrep", raw),
};

export const opengrep: ToolAdapter = {
  name: "opengrep",
  category: "sast",
  // No official OpenGrep image yet (only broken third-party ones) — native-only.
  argv: (target) => ["scan", "--json", "--quiet", "--config", "auto", target],
  parse: (raw) => parseSemgrep("opengrep", raw),
};
