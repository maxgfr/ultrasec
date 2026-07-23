import type { Finding } from "../types.js";
import type { ToolAdapter } from "./run.js";
import { makeToolFinding, normalizeSeverity } from "./normalize.js";

// bandit → Python AST security linter. Finds dangerous *idioms* a taint engine
// can't see because they're single-call primitives, not data flows: `shell=True`,
// `eval`/`exec`, weak hashes (md5/sha1), `pickle`/`yaml.load`, `verify=False`,
// `assert` in prod, flask `debug=True`, hardcoded tmp paths. `-ll -ii` reports
// only medium+ severity AND medium+ confidence, keeping the AI tier's noise down.
export const bandit: ToolAdapter = {
  name: "bandit",
  category: "sast",
  // NB the image lives at pycqa/bandit/bandit (the publish workflow appends the
  // repo name again under the org path) — a plain ghcr.io/pycqa/bandit:* tag 404s.
  // Upstream also only ever pushes `latest` (no versioned tags), so that's the
  // sole usable tag here regardless of the latest-by-default policy.
  dockerImage: "ghcr.io/pycqa/bandit/bandit:latest",
  argv: (target) => ["-r", target, "-f", "json", "-ll", "-ii", "-q"],
  parse(raw): Finding[] {
    const data = JSON.parse(raw || "{}") as any;
    const out: Finding[] = [];
    for (const r of data.results ?? []) {
      const cweId = r.issue_cwe?.id;
      const conf = String(r.issue_confidence ?? "").toLowerCase();
      out.push(
        makeToolFinding({
          tool: "bandit",
          category: "sast",
          ident: `${r.test_id}:${r.filename}:${r.line_number}`,
          title: `${r.test_id} ${r.test_name ?? ""}`.trim(),
          severity: normalizeSeverity(r.issue_severity, "medium"),
          confidence: conf === "high" ? "high" : conf === "low" ? "low" : "medium",
          message: r.issue_text || r.test_name || r.test_id,
          file: r.filename,
          line: r.line_number,
          cwe: cweId != null ? `CWE-${cweId}` : undefined,
          references: [r.more_info, r.issue_cwe?.link].filter(Boolean),
        }),
      );
    }
    return out;
  },
};
