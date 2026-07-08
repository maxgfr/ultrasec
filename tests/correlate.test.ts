import { describe, it, expect } from "vitest";
import { correlate } from "../src/tools/correlate.js";
import { makeToolFinding } from "../src/tools/normalize.js";
import type { Finding } from "../src/types.js";

const dep = (tool: string, ident: string, sev: Finding["severity"], opts: { aliases?: string[]; pkg: string; version: string; file?: string; line?: number }) =>
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

  // NodeGoat regression (eval P0.3b): the same advisory used to be emitted once
  // per installed version of the package (qs ×5, lodash ×5…) — ~45% headline
  // inflation. One advisory on one package = ONE finding; per-version instances
  // are evidence, kept in `locations[]`.
  it("merges the same CVE across different versions of the same package, recording per-version locations", () => {
    const a = dep("osv-scanner", "CVE-2021-23337", "medium", { pkg: "lodash", version: "3.0.0", file: "package-lock.json", line: 1 });
    const b = dep("osv-scanner", "CVE-2021-23337", "high", { pkg: "lodash", version: "4.17.20", file: "package-lock.json", line: 1 });
    const c = dep("trivy", "CVE-2021-23337", "high", { pkg: "lodash", version: "4.17.20", file: "package-lock.json", line: 1 });
    const out = correlate([a, b, c]);
    expect(out).toHaveLength(1);
    const f = out[0]!;
    expect(f.severity).toBe("high");
    expect(f.sources).toEqual(["osv-scanner", "trivy"]);
    expect(f.locations).toEqual([
      { file: "package-lock.json", line: 1, version: "3.0.0" },
      { file: "package-lock.json", line: 1, version: "4.17.20" },
    ]);
  });

  it("does NOT merge the same CVE across different packages", () => {
    const a = dep("trivy", "CVE-2024-0001", "high", { pkg: "lodash", version: "4.17.20" });
    const b = dep("trivy", "CVE-2024-0001", "high", { pkg: "underscore", version: "1.13.0" });
    expect(correlate([a, b])).toHaveLength(2);
  });

  it("returns unique ids over the NodeGoat shape (same advisory at the same lockfile, N versions)", () => {
    const versions = ["0.6.6", "5.2.1", "6.2.1", "6.3.2", "6.5.2"];
    const input = versions.map((v) => dep("osv-scanner", "CVE-2022-24999", "high", { pkg: "qs", version: v, file: "package-lock.json", line: 1 }));
    // Pre-correlate the raw findings must already be distinguishable (version in the id hash).
    expect(new Set(input.map((f) => f.id)).size).toBe(versions.length);
    const out = correlate(input);
    expect(out).toHaveLength(1);
    expect(out[0]!.locations).toHaveLength(versions.length);
    expect(new Set(out.map((f) => f.id)).size).toBe(out.length);
  });

  it("is idempotent across the cross-version merge (locations neither duplicated nor lost, incremental instance folds in)", () => {
    const a = dep("osv-scanner", "CVE-2021-23337", "high", { pkg: "lodash", version: "3.0.0", file: "package-lock.json", line: 1 });
    const b = dep("osv-scanner", "CVE-2021-23337", "high", { pkg: "lodash", version: "4.17.20", file: "package-lock.json", line: 1 });
    const once = correlate([a, b]);
    expect(correlate(once)).toEqual(once);
    // A later pass surfacing a NEW instance of the same advisory folds into the merged rep.
    const c = dep("osv-scanner", "CVE-2021-23337", "high", { pkg: "lodash", version: "2.4.2", file: "app/package-lock.json", line: 1 });
    const merged = correlate([...once, c]);
    expect(merged).toHaveLength(1);
    expect(merged[0]!.locations).toEqual([
      { file: "app/package-lock.json", line: 1, version: "2.4.2" },
      { file: "package-lock.json", line: 1, version: "3.0.0" },
      { file: "package-lock.json", line: 1, version: "4.17.20" },
    ]);
  });
});

describe("makeToolFinding — id identity", () => {
  it("gives distinct ids to the same advisory at the same location for different versions", () => {
    const a = dep("osv-scanner", "CVE-2022-24999", "high", { pkg: "qs", version: "5.2.1", file: "package-lock.json", line: 1 });
    const b = dep("osv-scanner", "CVE-2022-24999", "high", { pkg: "qs", version: "6.5.2", file: "package-lock.json", line: 1 });
    expect(a.id).not.toBe(b.id);
  });

  it("keeps the id unchanged for version-less findings (sast/secret/config ids stable)", () => {
    const a = makeToolFinding({
      tool: "semgrep",
      category: "sast",
      ident: "rule:src/a.js:3",
      title: "rule",
      severity: "high",
      message: "m",
      file: "src/a.js",
      line: 3,
    });
    const b = makeToolFinding({
      tool: "semgrep",
      category: "sast",
      ident: "rule:src/a.js:3",
      title: "rule",
      severity: "high",
      message: "m",
      file: "src/a.js",
      line: 3,
    });
    expect(a.id).toBe(b.id);
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
    const taint: Finding = {
      id: "t1",
      category: "taint",
      title: "flow",
      severity: "high",
      confidence: "medium",
      message: "m",
      tool: "ultrasec",
      status: "open",
    };
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

  // Regression: co-location is NOT corroboration. A standalone finding of a
  // DIFFERENT vuln class that merely lands on a taint source/hop/sink line was
  // silently consumed (the distinct finding vanished) and its verdict reasoning
  // was misattributed onto the unrelated taint finding. It must now survive.
  it("does NOT fold a co-located standalone with an absent CWE (authz finding preserved)", () => {
    const taint = taintFinding("t1"); // CWE-89, SOURCE node src/server.js:10
    const authz = makeToolFinding({
      tool: "deepsec",
      category: "authz",
      ident: "missing-access-control:src/server.js:10",
      title: "Broken access control",
      severity: "medium",
      message: "missing authorization check",
      file: "src/server.js",
      line: 10, // exactly the taint SOURCE line — but no CWE → not the same vuln
    });
    authz.priorAnalysis = { tool: "deepsec", revalidationVerdict: "false-positive", reasoning: "behind auth middleware" };
    const out = correlate([taint, authz]);
    expect(out).toHaveLength(2); // the authz finding is NOT consumed
    const t = out.find((f) => f.tool === "ultrasec")!;
    expect(t.sources ?? ["ultrasec"]).toEqual(["ultrasec"]); // not corroborated
    expect(t.priorAnalysis).toBeUndefined(); // the authz verdict is NOT misattributed onto the SQLi
    expect(out.some((f) => f.category === "authz")).toBe(true); // distinct finding survives standalone
  });

  it("does NOT fold a co-located standalone whose CWE differs from the taint's", () => {
    const taint = taintFinding("t1"); // CWE-89
    const out = correlate([taint, sast("deepsec", "CWE-862", "src/db.js", 6, "high")]); // same sink line, different CWE
    expect(out).toHaveLength(2);
    expect(out.find((f) => f.tool === "ultrasec")!.sources ?? ["ultrasec"]).toEqual(["ultrasec"]);
  });

  // Orphan-sink candidates are also `tool:"ultrasec"` (category "sast", sink, no
  // path) — a scanner flagging the same line+CWE corroborates them the same way.
  it("folds a co-located same-CWE tool finding into an orphan-sink candidate", () => {
    const orphan: Finding = {
      id: "sink1",
      category: "sast",
      cwe: "CWE-89",
      title: "SQL injection: query() sink (no source path found)",
      severity: "high",
      confidence: "low",
      message: "m",
      tool: "ultrasec",
      status: "open",
      sink: { file: "src/db.js", line: 11, kind: "sql" },
    };
    const out = correlate([orphan, sast("semgrep", "CWE-89", "src/db.js", 11, "medium")]);
    expect(out).toHaveLength(1);
    expect(out[0]!.id).toBe("sink1");
    expect(out[0]!.sources).toEqual(["semgrep", "ultrasec"]);
  });

  it("is idempotent over a mixed taint + orphan-sink + tool + dep set", () => {
    const mixed: Finding[] = [
      taintFinding("t1"),
      sast("deepsec", "CWE-89", "src/db.js", 6, "high"), // corroborates t1's sink
      sast("semgrep", "CWE-79", "src/view.js", 3, "medium"), // standalone survivor
      dep("trivy", "CVE-2021-23337", "high", { pkg: "lodash", version: "4.17.20" }),
      dep("osv-scanner", "GHSA-35jh-r3h4-6jhm", "medium", { aliases: ["CVE-2021-23337"], pkg: "lodash", version: "4.17.20" }),
    ];
    const once = correlate(mixed);
    const twice = correlate(once);
    expect(twice).toEqual(once);
  });
});
