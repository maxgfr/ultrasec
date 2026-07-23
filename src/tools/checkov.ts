import type { Finding } from "../types.js";
import type { ToolAdapter } from "./run.js";
import { makeToolFinding, normalizeSeverity } from "./normalize.js";

// checkov → IaC / misconfig with a CROSS-RESOURCE graph (Terraform, CloudFormation,
// Kubernetes, Dockerfile, Helm, ARM…). It catches relationship policies trivy's
// per-block engine can't express (e.g. "this SG is attached to a public ENI").
// `-o json` emits either one object or an array (one per detected framework);
// `--soft-fail` keeps exit 0, `--compact --quiet` drops code blocks + passed checks.
// Per-finding severity is null without a Prisma key ⇒ default to medium.
export const checkov: ToolAdapter = {
  name: "checkov",
  category: "config",
  dockerImage: "bridgecrew/checkov:latest",
  argv: (target) => ["-d", target, "-o", "json", "--compact", "--quiet", "--soft-fail"],
  parse(raw): Finding[] {
    const data = JSON.parse(raw || "{}") as any;
    const blocks: any[] = Array.isArray(data) ? data : [data];
    const out: Finding[] = [];
    for (const b of blocks) {
      for (const c of b?.results?.failed_checks ?? []) {
        // file_path is relative to the scanned dir but carries a leading slash.
        const file = String(c.file_path ?? "").replace(/^\/+/, "");
        const line = Array.isArray(c.file_line_range) ? c.file_line_range[0] : undefined;
        out.push(
          makeToolFinding({
            tool: "checkov",
            category: "config",
            ident: `${c.check_id}:${file}:${line ?? ""}`,
            title: `${c.check_id} ${c.check_name ?? ""}`.trim(),
            severity: normalizeSeverity(c.severity, "medium"),
            message: `${c.check_name || c.check_id}${c.resource ? ` (${c.resource})` : ""}`,
            file: file || undefined,
            line: typeof line === "number" ? line : undefined,
            references: [c.guideline].filter(Boolean),
          }),
        );
      }
    }
    return out;
  },
};
