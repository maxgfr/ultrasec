import { basename } from "node:path";
import type { Finding, Severity } from "../types.js";
import type { ToolAdapter } from "./run.js";
import { makeToolFinding } from "./normalize.js";
import { walk } from "../walk.js";

// hadolint → Dockerfile linter with ShellCheck embedded, so it audits the bash
// inside `RUN` instructions — something neither trivy misconfig nor checkov do.
// It scans explicit files (not a directory), so the adapter enumerates Dockerfiles
// and feeds them via `enumerate()`. Output is a top-level JSON array.
const LEVEL: Record<string, Severity> = { error: "high", warning: "medium", info: "low", style: "info" };

/** A Dockerfile by any common convention. */
function isDockerfile(rel: string): boolean {
  const b = basename(rel).toLowerCase();
  return b === "dockerfile" || b === "containerfile" || b.startsWith("dockerfile.") || b.endsWith(".dockerfile");
}

export const hadolint: ToolAdapter = {
  name: "hadolint",
  category: "config",
  dockerImage: "hadolint/hadolint:v2.12.0",
  argv: () => ["--format", "json", "--no-fail"],
  enumerate: (repo) =>
    walk(repo)
      .map((f) => f.rel)
      .filter(isDockerfile),
  parse(raw): Finding[] {
    const arr = JSON.parse(raw || "[]") as any;
    if (!Array.isArray(arr)) return [];
    return arr.map((d: any) =>
      makeToolFinding({
        tool: "hadolint",
        category: "config",
        ident: `${d.code}:${d.file}:${d.line}`,
        title: `${d.code} ${d.message ?? ""}`.trim(),
        severity: LEVEL[String(d.level ?? "").toLowerCase()] ?? "low",
        message: `${d.code}: ${d.message ?? ""}`.trim(),
        file: d.file,
        line: d.line,
        references: String(d.code ?? "").startsWith("DL") ? [`https://github.com/hadolint/hadolint/wiki/${d.code}`] : [],
      }),
    );
  },
};
