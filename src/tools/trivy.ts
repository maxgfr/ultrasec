import type { Finding } from "../types.js";
import type { ToolAdapter } from "./run.js";
import { makeToolFinding, normalizeSeverity, firstCwe, cvesIn } from "./normalize.js";

// Trivy `fs` scan → dependency CVEs, secrets, and IaC/misconfig. One physical
// file can appear in several Result blocks; the file path lives on the parent
// Result.Target, not on the finding. `Results` may be absent ⇒ zero findings.
export const trivy: ToolAdapter = {
  name: "trivy",
  category: "dep",
  dockerImage: "ghcr.io/aquasecurity/trivy:0.71.1",
  argv: (target) => ["fs", "--scanners", "vuln,secret,misconfig", "--format", "json", "--quiet", target],
  parse(raw): Finding[] {
    const data = JSON.parse(raw || "{}") as any;
    const out: Finding[] = [];
    for (const r of data.Results ?? []) {
      const target: string = r.Target ?? "";
      for (const v of r.Vulnerabilities ?? []) {
        out.push(
          makeToolFinding({
            tool: "trivy",
            category: "dep",
            ident: v.VulnerabilityID,
            title: v.Title || `${v.PkgName}: ${v.VulnerabilityID}`,
            severity: normalizeSeverity(v.Severity, "medium"),
            message:
              `${v.PkgName}@${v.InstalledVersion}: ${v.Title || v.Description || v.VulnerabilityID}` + (v.FixedVersion ? ` (fixed in ${v.FixedVersion})` : ""),
            file: target,
            cwe: firstCwe(v.CweIDs),
            references: [v.PrimaryURL, ...(v.References ?? [])].filter(Boolean),
            pkg: v.PkgName,
            version: v.InstalledVersion,
            // VulnerabilityID may be a GHSA; surface any CVE in the refs so the
            // cross-tool correlator can match it against osv/grype on the CVE.
            aliases: [v.VulnerabilityID, ...cvesIn(v.PrimaryURL, v.References)],
          }),
        );
      }
      for (const s of r.Secrets ?? []) {
        out.push(
          makeToolFinding({
            tool: "trivy",
            category: "secret",
            ident: `${s.RuleID}:${s.StartLine}`,
            title: s.Title || s.RuleID,
            severity: normalizeSeverity(s.Severity, "high"),
            message: `Hardcoded secret (${s.Title || s.RuleID}) at ${target}:${s.StartLine}`,
            file: target,
            line: s.StartLine,
            cwe: "CWE-798",
          }),
        );
      }
      for (const mc of r.Misconfigurations ?? []) {
        const line = mc.CauseMetadata?.StartLine;
        out.push(
          makeToolFinding({
            tool: "trivy",
            category: "config",
            ident: mc.AVDID || mc.ID,
            title: mc.Title || mc.ID,
            severity: normalizeSeverity(mc.Severity, "medium"),
            message: `${mc.ID} ${mc.Title}: ${mc.Message || mc.Description || ""}`.trim(),
            file: target,
            line: typeof line === "number" ? line : undefined,
            references: [mc.PrimaryURL, ...(mc.References ?? [])].filter(Boolean),
          }),
        );
      }
    }
    return out;
  },
};
