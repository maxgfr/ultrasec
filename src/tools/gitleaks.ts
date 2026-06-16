import type { Finding } from "../types.js";
import type { ToolAdapter } from "./run.js";
import { makeToolFinding } from "./normalize.js";

// gitleaks → hardcoded secrets. Output is a top-level JSON ARRAY (no wrapper),
// PascalCase keys, no severity (assign high) and no CWE (CWE-798). `--no-git`
// scans the working tree so it works on non-git repos too; `--redact` keeps the
// raw secret out of the dossier.
export const gitleaks: ToolAdapter = {
  name: "gitleaks",
  category: "secret",
  dockerImage: "ghcr.io/gitleaks/gitleaks:v8.30.1",
  // `--report-path -` is gitleaks' documented stdout sink (json to a file otherwise);
  // `--exit-code 0` so "leaks found" (normally exit 1) isn't treated as a tool failure.
  argv: (target) => ["detect", "--no-git", "--source", target, "--report-format", "json", "--report-path", "-", "--no-banner", "--redact", "--exit-code", "0"],
  parse(raw): Finding[] {
    const arr = JSON.parse(raw || "[]") as any;
    if (!Array.isArray(arr)) return [];
    return arr.map((f: any) =>
      makeToolFinding({
        tool: "gitleaks",
        category: "secret",
        ident: `${f.RuleID}:${f.File}:${f.StartLine}`,
        title: f.Description || f.RuleID,
        severity: "high",
        message: `Hardcoded secret (${f.Description || f.RuleID}) at ${f.File}:${f.StartLine}`,
        file: f.File,
        line: f.StartLine,
        cwe: "CWE-798",
      }),
    );
  },
};
