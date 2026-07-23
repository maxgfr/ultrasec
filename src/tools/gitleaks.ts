import { existsSync } from "node:fs";
import { join } from "node:path";
import type { Finding } from "../types.js";
import type { ToolAdapter } from "./run.js";
import { makeToolFinding } from "./normalize.js";

// gitleaks → hardcoded secrets. Output is a top-level JSON ARRAY (no wrapper),
// PascalCase keys, no severity (assign high) and no CWE (CWE-798). `--redact`
// keeps the raw secret out of the dossier.
//
// When the target is a real git repo we scan the FULL HISTORY (catches secrets
// that were committed then deleted — invisible to a working-tree scan, and a
// classic real-world leak). For non-git dirs — and docker runs, where the /work
// mount isn't a host path we can probe — we fall back to `--no-git` (working
// tree) so the scan always works.
export const gitleaks: ToolAdapter = {
  name: "gitleaks",
  category: "secret",
  dockerImage: "ghcr.io/gitleaks/gitleaks:latest",
  // `--report-path -` is gitleaks' documented stdout sink (json to a file otherwise);
  // `--exit-code 0` so "leaks found" (normally exit 1) isn't treated as a tool failure.
  argv: (target) => {
    const onHost = existsSync(target);
    const hasGit = onHost && existsSync(join(target, ".git"));
    const base = ["detect", "--source", target, "--report-format", "json", "--report-path", "-", "--no-banner", "--redact", "--exit-code", "0"];
    return hasGit ? base : [...base, "--no-git"];
  },
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
