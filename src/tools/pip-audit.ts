import { existsSync } from "node:fs";
import { join } from "node:path";
import type { Finding } from "../types.js";
import type { ToolAdapter } from "./run.js";
import { makeToolFinding } from "./normalize.js";

// pip-audit → PyPI/OSV advisory scanner for `requirements.txt`. Unlike
// trivy/osv-scanner (which query a locally-cached vuln DB), it hits PyPI's JSON
// API or OSV.dev on every single invocation — there's no offline mode — so it's
// gated behind `network: true` and skipped under `--offline`.
export const pipAudit: ToolAdapter = {
  name: "pip-audit",
  category: "dep",
  network: true,
  applicable: (repo) => (existsSync(join(repo, "requirements.txt")) ? null : "no requirements.txt"),
  argv: () => ["-r", "requirements.txt", "-f", "json", "--progress-spinner", "off"],
  parse(raw): Finding[] {
    let data: any;
    try {
      data = JSON.parse(raw || "{}");
    } catch {
      return [];
    }
    // Modern pip-audit wraps deps in `{dependencies: [...]}`; tolerate the bare
    // top-level array some older/vendored builds emit.
    const deps: any[] = Array.isArray(data) ? data : Array.isArray(data?.dependencies) ? data.dependencies : [];
    const out: Finding[] = [];
    for (const dep of deps) {
      const name = dep?.name;
      const version = dep?.version;
      for (const v of dep?.vulns ?? []) {
        const fixed = (v.fix_versions ?? []).join(", ");
        out.push(
          makeToolFinding({
            tool: "pip-audit",
            category: "dep",
            ident: v.id,
            title: `${name}: ${v.id}`,
            // pip-audit reports no severity at all — default to medium; when this
            // merges with a trivy/osv finding on the same CVE, correlate() takes
            // the MAX severity across sources, so a real (higher) severity wins.
            severity: "medium",
            message: `${name}@${version}: ${v.description || v.id}` + (fixed ? ` (fixed in ${fixed})` : ""),
            file: "requirements.txt",
            pkg: name,
            version,
            // v.id is usually PYSEC-…/GHSA-…; v.aliases carries the CVE — the join key.
            aliases: [v.id, ...(v.aliases ?? [])],
          }),
        );
      }
    }
    return out;
  },
};
