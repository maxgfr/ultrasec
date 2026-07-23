import type { Finding, Severity } from "../types.js";
import type { ToolAdapter } from "./run.js";
import { makeToolFinding, normalizeSeverity } from "./normalize.js";
import { deriveSeverity } from "./cvss.js";

// grype → Anchore SBOM-based dependency vulnerability scanner (pairs with syft;
// also scans a plain directory when no SBOM was generated this run). Severity
// is usually a label, but grype emits "Unknown" when its DB has none for that
// advisory — fall back to the CVSS base score, the same move osv.ts makes for
// its own label-less rows. `relatedVulnerabilities` is how grype cross-references
// its native id (often a GHSA) to the CVE — surfaced as aliases so the cross-tool
// correlator can join on it.
function grypeSeverity(v: any): Severity {
  const label = v.severity;
  if (label && !/^unknown$/i.test(String(label))) return normalizeSeverity(label, "medium");
  const c = v.cvss?.[0] ?? {};
  const fallback = c.vector || (c.metrics?.baseScore != null ? String(c.metrics.baseScore) : "");
  return deriveSeverity(fallback, "medium");
}

export const grype: ToolAdapter = {
  name: "grype",
  category: "dep",
  // Prefer the SBOM generated this run (faster, no re-walk of the tree) when one
  // exists; otherwise fall back to scanning the repo directory directly.
  argv: (target, ctx) => (ctx?.sbom ? [`sbom:${ctx.sbom}`, "-o", "json", "-q"] : [`dir:${target}`, "-o", "json", "-q"]),
  parse(raw): Finding[] {
    let data: any;
    try {
      data = JSON.parse(raw || "{}");
    } catch {
      return [];
    }
    const matches = Array.isArray(data?.matches) ? data.matches : [];
    const out: Finding[] = [];
    for (const m of matches.filter(Boolean)) {
      const v = m?.vulnerability ?? {};
      const artifact = m?.artifact ?? {};
      const related: string[] = (m?.relatedVulnerabilities ?? []).map((r: any) => r?.id).filter(Boolean);
      const fixed = (v.fix?.versions ?? []).join(", ");
      out.push(
        makeToolFinding({
          tool: "grype",
          category: "dep",
          ident: v.id,
          title: `${artifact.name}: ${v.id}`,
          severity: grypeSeverity(v),
          message: `${artifact.name}@${artifact.version}: ${v.id}` + (fixed ? ` (fixed in ${fixed})` : ""),
          file: artifact.locations?.[0]?.path ?? "",
          references: [v.dataSource, ...(v.urls ?? [])].filter(Boolean),
          pkg: artifact.name,
          version: artifact.version,
          // v.id may be a GHSA; relatedVulnerabilities carries the CVE — the join key.
          aliases: [v.id, ...related],
        }),
      );
    }
    return out;
  },
};
