import { describe, it, expect } from "vitest";
import { correlate } from "../src/tools/correlate.js";
import { makeToolFinding } from "../src/tools/normalize.js";
import type { Finding } from "../src/types.js";

const dep = (tool: string, ident: string, sev: Finding["severity"], opts: { aliases?: string[]; pkg: string; version: string }) =>
  makeToolFinding({ tool, category: "dep", ident, title: ident, severity: sev, message: `${opts.pkg}@${opts.version}`, ...opts });

const sast = (tool: string, cwe: string, file: string, line: number, sev: Finding["severity"]) =>
  makeToolFinding({ tool, category: "sast", ident: `${tool}.rule:${file}:${line}`, title: "rule", severity: sev, message: "m", file, line, cwe });

describe("correlate — dep (SCA) cross-tool merge", () => {
  it("merges the same CVE on the same package@version across tools, unioning sources/aliases and taking max severity", () => {
    const a = dep("trivy", "CVE-2021-23337", "high", { pkg: "lodash", version: "4.17.20" });
    const b = dep("osv-scanner", "GHSA-35jh-r3h4-6jhm", "medium", { aliases: ["CVE-2021-23337"], pkg: "lodash", version: "4.17.20" });
    const out = correlate([a, b]);
    expect(out).toHaveLength(1);
    expect(out[0]!.severity).toBe("high");
    expect(out[0]!.sources).toEqual(["osv-scanner", "trivy"]);
    expect(out[0]!.cve).toBe("CVE-2021-23337");
    expect(out[0]!.aliases).toContain("GHSA-35JH-R3H4-6JHM");
    expect(out[0]!.confidence).toBe("high"); // corroborated by 2 tools
  });

  it("does NOT merge distinct vulns in the same package", () => {
    const a = dep("trivy", "CVE-2021-23337", "high", { pkg: "lodash", version: "4.17.20" });
    const b = dep("trivy", "CVE-2020-8203", "high", { pkg: "lodash", version: "4.17.20" });
    expect(correlate([a, b])).toHaveLength(2);
  });

  it("does NOT merge the same CVE across different package versions", () => {
    const a = dep("trivy", "CVE-2021-23337", "high", { pkg: "lodash", version: "4.17.20" });
    const b = dep("osv-scanner", "CVE-2021-23337", "high", { pkg: "lodash", version: "3.0.0" });
    expect(correlate([a, b])).toHaveLength(2);
  });
});

describe("correlate — non-dep merge by category+cwe+location", () => {
  it("merges two SAST tools flagging the same file:line+CWE", () => {
    const out = correlate([sast("semgrep", "CWE-89", "src/app.py", 42, "high"), sast("opengrep", "CWE-89", "src/app.py", 42, "medium")]);
    expect(out).toHaveLength(1);
    expect(out[0]!.sources).toEqual(["opengrep", "semgrep"]);
    expect(out[0]!.severity).toBe("high");
  });

  it("keeps findings at different lines separate", () => {
    expect(correlate([sast("semgrep", "CWE-89", "src/app.py", 42, "high"), sast("semgrep", "CWE-89", "src/app.py", 99, "high")])).toHaveLength(2);
  });
});

// A taint finding with a real cross-file path (source → sink).
function taintFinding(id: string, severity: Finding["severity"] = "high"): Finding {
  return {
    id,
    category: "taint",
    cwe: "CWE-89",
    title: "flow",
    severity,
    confidence: "medium",
    message: "m",
    tool: "ultrasec",
    status: "open",
    source: { file: "src/server.js", line: 10 },
    sink: { file: "src/db.js", line: 6 },
    path: [
      { file: "src/server.js", line: 10, why: "source" },
      { file: "src/db.js", line: 6, why: "sink" },
    ],
  };
}

describe("correlate — invariants", () => {
  it("leaves an un-corroborated taint candidate's fields untouched", () => {
    const taint: Finding = { id: "t1", category: "taint", title: "flow", severity: "high", confidence: "medium", message: "m", tool: "ultrasec", status: "open" };
    const out = correlate([taint]);
    expect(out).toHaveLength(1);
    expect(out[0]!.tool).toBe("ultrasec");
    expect(out[0]!.category).toBe("taint");
    expect(out[0]!.severity).toBe("high");
    expect(out[0]).toEqual(taint); // fields untouched (identity preserved when no corroboration)
  });

  it("is idempotent", () => {
    const a = dep("trivy", "CVE-2021-23337", "high", { pkg: "lodash", version: "4.17.20" });
    const b = dep("osv-scanner", "GHSA-1", "medium", { aliases: ["CVE-2021-23337"], pkg: "lodash", version: "4.17.20" });
    const once = correlate([a, b]);
    const twice = correlate(once);
    expect(twice).toHaveLength(once.length);
    expect(twice[0]!.sources).toEqual(once[0]!.sources);
  });

  it("returns [] for no input", () => {
    expect(correlate([])).toEqual([]);
  });
});

describe("correlate — taint corroboration (Phase 6 relaxation)", () => {
  it("folds a standalone tool finding on a taint sink node into the taint finding's sources + bumps confidence, and consumes it", () => {
    const taint = taintFinding("t1");
    const ds = sast("deepsec", "CWE-89", "src/db.js", 6, "high"); // exact sink line of t1
    const out = correlate([taint, ds]);
    expect(out).toHaveLength(1); // standalone consumed
    const t = out[0]!;
    expect(t.tool).toBe("ultrasec"); // still the taint finding
    expect(t.sources).toEqual(["deepsec", "ultrasec"]);
    expect(t.confidence).toBe("high"); // ≥2 sources → corroborated
  });

  it("CORRUPTION GUARD: path/source/sink/title/severity are byte-identical after corroboration", () => {
    const taint = taintFinding("t1");
    const before = JSON.parse(JSON.stringify({ path: taint.path, source: taint.source, sink: taint.sink, title: taint.title, severity: taint.severity }));
    const out = correlate([taint, sast("deepsec", "CWE-89", "src/db.js", 6, "critical")]);
    const t = out[0]!;
    expect(t.path).toEqual(before.path);
    expect(t.source).toEqual(before.source);
    expect(t.sink).toEqual(before.sink);
    expect(t.title).toBe(before.title);
    expect(t.severity).toBe(before.severity); // a higher-sev tool finding does NOT raise the taint severity
  });

  it("carries a consumed finding's priorAnalysis onto the taint finding (signal preserved)", () => {
    const taint = taintFinding("t1");
    const ds = sast("deepsec", "CWE-89", "src/db.js", 6, "high");
    ds.priorAnalysis = { tool: "deepsec", revalidationVerdict: "true-positive", reasoning: "reaches the DB unsanitized" };
    const out = correlate([taint, ds]);
    expect(out).toHaveLength(1);
    expect(out[0]!.priorAnalysis).toEqual(ds.priorAnalysis);
    expect(out[0]!.sources).toContain("deepsec");
  });

  it("corroborates on a SOURCE or HOP node, not only the sink", () => {
    const taint = taintFinding("t1");
    const out = correlate([taint, sast("deepsec", "CWE-89", "src/server.js", 10, "high")]); // the source node
    expect(out).toHaveLength(1);
    expect(out[0]!.sources).toContain("deepsec");
  });

  it("leaves a tool finding STANDALONE when it is NOT on any taint path node", () => {
    const taint = taintFinding("t1");
    const elsewhere = sast("deepsec", "CWE-79", "src/other.js", 99, "medium");
    const out = correlate([taint, elsewhere]);
    expect(out).toHaveLength(2); // both kept
    expect(out.find((f) => f.tool === "ultrasec")!.sources ?? ["ultrasec"]).toEqual(["ultrasec"]);
  });

  it("is idempotent across the corroboration relaxation", () => {
    const once = correlate([taintFinding("t1"), sast("deepsec", "CWE-89", "src/db.js", 6, "high")]);
    const twice = correlate(once);
    expect(twice).toHaveLength(once.length);
    expect(twice[0]!.sources).toEqual(once[0]!.sources);
    expect(twice[0]!.path).toEqual(once[0]!.path);
  });
});
