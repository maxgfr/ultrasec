import type { Finding } from "../types.js";
import type { ToolAdapter } from "./run.js";
import { makeToolFinding } from "./normalize.js";
import { deriveSeverity } from "./cvss.js";

// cargo-audit → RustSec advisories for Cargo.lock. Runs in the repo cwd. No
// severity label (derive from advisory.cvss vector, often null) and no CWE.
// Informational warnings (unmaintained/unsound/yanked/notice) become low findings.
export const cargoAudit: ToolAdapter = {
  name: "cargo-audit",
  category: "dep",
  argv: () => ["audit", "--format", "json"],
  parse(raw): Finding[] {
    const data = JSON.parse(raw || "{}") as any;
    const out: Finding[] = [];

    for (const item of data.vulnerabilities?.list ?? []) {
      const adv = item.advisory ?? {};
      const pkg = item.package ?? {};
      const patched = (item.versions?.patched ?? []).join(", ");
      out.push(
        makeToolFinding({
          tool: "cargo-audit",
          category: "dep",
          ident: adv.id,
          title: adv.title || adv.id,
          severity: deriveSeverity(adv.cvss, "high"),
          message: `${pkg.name}@${pkg.version}: ${adv.title || adv.id}` + (patched ? ` (patched: ${patched})` : ""),
          file: "Cargo.lock",
          references: [adv.url, ...(adv.aliases ?? [])].filter(Boolean),
        }),
      );
    }

    const warnings = data.warnings ?? {};
    for (const kind of Object.keys(warnings)) {
      for (const w of warnings[kind] ?? []) {
        const adv = w.advisory ?? {};
        const pkg = w.package ?? {};
        out.push(
          makeToolFinding({
            tool: "cargo-audit",
            category: "dep",
            ident: adv.id || `${kind}:${pkg.name}`,
            title: adv.title || `${pkg.name} is ${kind}`,
            severity: "low",
            confidence: "low",
            message: `${pkg.name}@${pkg.version}: ${kind}${adv.title ? ` — ${adv.title}` : ""}`,
            file: "Cargo.lock",
            references: adv.url ? [adv.url] : [],
          }),
        );
      }
    }
    return out;
  },
};
