import type { Finding } from "../types.js";
import type { ToolAdapter } from "./run.js";
import { makeToolFinding, normalizeSeverity } from "./normalize.js";
import { walk } from "../walk.js";

// gosec → Go security checker, stdlib-aware in ways generic SAST is not:
// `math/rand` where crypto/rand is required, `tls.Config{InsecureSkipVerify:true}`,
// `exec.Command` with a tainted arg, SQL string concat, unhandled errors, file
// perms. Scans `./...` from the repo root (cwd is the repo natively, /work in
// docker). `-no-fail` keeps findings from failing the process. Do not use
// `-quiet`: it can suppress the entire report when packages cannot load.
// NB gosec emits line/column/cwe.id as STRINGS.
export const gosec: ToolAdapter = {
  name: "gosec",
  cacheable: true,
  category: "sast",
  dockerImage: "ghcr.io/securego/gosec:latest",
  // gosec exits 1 with EMPTY stdout and EMPTY stderr on a repo that has no Go —
  // no output to parse and no diagnostic to report, so the run surfaced as an
  // unexplained failure on every non-Go project. Ask the question `cppcheck`
  // already asks instead, and skip cleanly.
  applicable: (repo) => (walk(repo).some((f) => /\.go$/i.test(f.rel)) ? null : "no Go sources"),
  argv: () => ["-fmt", "json", "-no-fail", "./..."],
  parse(raw): Finding[] {
    const data = JSON.parse(raw) as any;
    if (!data || !Array.isArray(data.Issues)) throw new Error("gosec did not return a valid Issues report");
    const errors = Object.values(data["Golang errors"] ?? {}).flat() as { error?: string }[];
    if (errors.length) throw new Error(`gosec could not analyze all packages: ${errors.map((e) => e.error ?? "package load error").join("; ")}`);
    const out: Finding[] = [];
    for (const i of data.Issues ?? []) {
      const line = parseInt(String(i.line).split("-")[0] ?? "", 10);
      const cweId = i.cwe?.id;
      out.push(
        makeToolFinding({
          tool: "gosec",
          category: "sast",
          ident: `${i.rule_id}:${i.file}:${i.line}`,
          title: `${i.rule_id} ${i.details ?? ""}`.trim(),
          severity: normalizeSeverity(i.severity, "medium"),
          confidence: String(i.confidence ?? "").toLowerCase() === "high" ? "high" : "medium",
          message: `${i.details || i.rule_id}`,
          file: i.file,
          line: Number.isNaN(line) ? undefined : line,
          cwe: cweId ? `CWE-${cweId}` : undefined,
          references: [i.cwe?.url].filter(Boolean),
        }),
      );
    }
    return out;
  },
};
