import type { Finding } from "../types.js";
import type { ToolAdapter } from "./run.js";
import { makeToolFinding, firstCwe, cvesIn } from "./normalize.js";
import { deriveSeverity } from "./cvss.js";

// osv-scanner → dependency vulnerabilities (lockfile-driven). Deeply nested:
// results[].packages[].vulnerabilities[]. Severity is not a label — derive it
// from groups[].max_severity (CVSS score string) or database_specific.severity.
export const osvScanner: ToolAdapter = {
  name: "osv-scanner",
  category: "dep",
  dockerImage: "ghcr.io/google/osv-scanner:v2.3.8",
  // v2 CLI: `scan source` walks a directory for lockfiles/manifests. JSON → stdout.
  argv: (target) => ["scan", "source", "--recursive", "--format", "json", target],
  parse(raw): Finding[] {
    const data = JSON.parse(raw || "{}") as any;
    const out: Finding[] = [];
    for (const res of data.results ?? []) {
      const src: string = res.source?.path ?? "";
      for (const pkg of res.packages ?? []) {
        const name = pkg.package?.name;
        const version = pkg.package?.version;
        const groupSev = new Map<string, string>();
        for (const g of pkg.groups ?? []) for (const id of g.ids ?? []) groupSev.set(id, g.max_severity);
        for (const v of pkg.vulnerabilities ?? []) {
          const db = v.database_specific ?? {};
          const sevStr: string = groupSev.get(v.id) ?? db.severity ?? "";
          const fixed = (v.affected ?? [])
            .flatMap((a: any) => (a.ranges ?? []).flatMap((r: any) => (r.events ?? []).map((e: any) => e.fixed)))
            .filter(Boolean)[0];
          const refs = (v.references ?? []).map((r: any) => r.url).filter(Boolean);
          out.push(
            makeToolFinding({
              tool: "osv-scanner",
              category: "dep",
              ident: v.id,
              title: v.summary || v.id,
              severity: deriveSeverity(sevStr, "medium"),
              message: `${name}@${version}: ${v.summary || v.id}` + (fixed ? ` (fixed in ${fixed})` : ""),
              file: src,
              cwe: firstCwe(db.cwe_ids),
              references: refs,
              pkg: name,
              version,
              // v.id is usually a GHSA; v.aliases carries the CVE — the join key.
              aliases: [...(v.aliases ?? []), ...cvesIn(refs)],
            }),
          );
        }
      }
    }
    return out;
  },
};
