import type { Finding } from "../types.js";
import type { ToolAdapter } from "./run.js";
import { makeToolFinding, parseJsonStream } from "./normalize.js";

// govulncheck → reachability-aware Go vulnerabilities. Output is a STREAM of
// concatenated JSON objects, each holding one of {config,progress,osv,finding}.
// Correlate finding.osv → the matching osv.id; trace[0] is the vulnerable call
// site (innermost frame). No severity/CWE — default reachable findings to high.
export const govulncheck: ToolAdapter = {
  name: "govulncheck",
  category: "dep",
  streaming: true,
  argv: () => ["-json", "./..."],
  parse(raw): Finding[] {
    const msgs = parseJsonStream(raw) as any[];
    const osvById = new Map<string, any>();
    for (const m of msgs) if (m?.osv?.id) osvById.set(m.osv.id, m.osv);

    const out: Finding[] = [];
    const seen = new Set<string>();
    for (const m of msgs) {
      const f = m?.finding;
      if (!f?.osv) continue;
      if (seen.has(f.osv)) continue; // one finding per advisory
      seen.add(f.osv);
      const osv = osvById.get(f.osv) ?? {};
      const top = (f.trace ?? [])[0] ?? {};
      const reachable = Boolean(top.function && top.position);
      out.push(
        makeToolFinding({
          tool: "govulncheck",
          category: "dep",
          ident: f.osv,
          title: osv.summary || f.osv,
          severity: reachable ? "high" : "medium",
          confidence: reachable ? "high" : "low",
          message:
            `${osv.summary || f.osv}` +
            (f.fixed_version ? ` (fixed in ${f.fixed_version})` : "") +
            (reachable ? ` — reachable via ${top.package}.${top.function}` : " — imported, reachability not proven"),
          file: top.position?.filename,
          line: top.position?.line,
          references: (osv.references ?? []).map((r: any) => r.url).filter(Boolean),
        }),
      );
    }
    return out;
  },
};
