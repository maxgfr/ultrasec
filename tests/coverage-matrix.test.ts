import { describe, it, expect, vi } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildCoverage, renderCoverageMd, enumeratedKindsOf, ASVS, STANDARDS, DEFAULT_STANDARD } from "../src/coverage.js";
import { runCoverage } from "../src/commands/coverage.js";
import { writeDossier, type Dossier } from "../src/store.js";
import { parseArgs } from "../src/util.js";
import type { Finding } from "../src/types.js";

const dossier = (findings: Finding[]): Dossier => ({
  manifest: {
    version: "0",
    schemaVersion: 7,
    repo: "/tmp/x",
    generatedNote: "",
    languages: ["javascript"],
    toolsRun: [],
    counts: { findings: findings.length, bySeverity: { critical: 0, high: findings.length, medium: 0, low: 0, info: 0 } },
  },
  findings,
  graph: { files: [], edges: [], symbolDefs: {} },
});

const f = (over: Partial<Finding>): Finding => ({
  id: "x",
  category: "taint",
  title: "t",
  severity: "high",
  confidence: "low",
  message: "m",
  tool: "ultrasec",
  status: "open",
  ...over,
});

describe("coverage matrix", () => {
  it("accounts for EVERY category in exactly one state", () => {
    // The whole point: nothing may be quietly skipped. A category with no bucket
    // is a category the report never mentions.
    const rows = buildCoverage(dossier([]));
    expect(rows).toHaveLength(ASVS.length);
    expect(rows.every((r) => ["engine", "examined", "unexamined"].includes(r.state))).toBe(true);
  });

  it("reports an empty audit as NOT EXAMINED, never as clean", () => {
    const rows = buildCoverage(dossier([]));
    expect(rows.every((r) => r.state === "unexamined")).toBe(true);
    expect(renderCoverageMd(rows)).toMatch(/is not\s+a clean bill of health/);
  });

  it("marks a category examined once a finding lands in it", () => {
    const rows = buildCoverage(dossier([f({ sink: { file: "a.js", line: 1, kind: "sql" } })]), ["sql"]);
    expect(rows.find((r) => r.id === "V5")!.state).toBe("examined");
  });

  it("counts a class the engine walked but this repo never exercised as enumerated, not as a gap", () => {
    // The pass ran; it simply found nothing. That is different from never looking.
    const rows = buildCoverage(dossier([f({ sink: { file: "a.js", line: 1, kind: "sql" } })]), ["sql", "ssrf"]);
    expect(rows.find((r) => r.id === "V13")!.state).toBe("engine");
  });

  it("names the judgment categories so 'not applicable' has to be argued", () => {
    const md = renderCoverageMd(buildCoverage(dossier([])));
    expect(md).toMatch(/Answer these explicitly/);
    expect(md).toMatch(/without a\s+reason is how coverage silently shrinks/);
    expect(md).toMatch(/Access control/);
    expect(md).toMatch(/Business logic/);
  });

  it("does not claim coverage of classes a source audit cannot speak to", () => {
    // Listing all 14 ASVS chapters would be exactly the coverage theatre this
    // file exists to avoid.
    expect(ASVS.map((c) => c.id)).not.toContain("V10");
  });
});

describe("pluggable standards", () => {
  it("ships the five packs and asvs is the default, unchanged", () => {
    expect(Object.keys(STANDARDS).sort()).toEqual(["asvs", "cwe-top25", "masvs", "owasp-api-top10", "owasp-top10"]);
    expect(DEFAULT_STANDARD).toBe("asvs");
    // The default path and an explicit "asvs" produce byte-identical rows.
    const d = dossier([f({ sink: { file: "a.js", line: 1, kind: "sql" } })]);
    expect(buildCoverage(d, ["sql"])).toEqual(buildCoverage(d, ["sql"], "asvs"));
    // asvs still maps 1:1 onto the ASVS chapter list.
    expect(buildCoverage(dossier([])).map((r) => r.id)).toEqual(ASVS.map((c) => c.id));
  });

  it("every pack accounts for each category in exactly one valid state", () => {
    for (const id of Object.keys(STANDARDS)) {
      const rows = buildCoverage(dossier([]), [], id);
      expect(rows).toHaveLength(STANDARDS[id]!.categories.length);
      expect(rows.every((r) => ["engine", "examined", "unexamined"].includes(r.state))).toBe(true);
    }
  });

  it("scores CWE-keyed items from a finding's cwe (config/auth detectors, no sink kind)", () => {
    // A TLS-verify-disabled finding (CWE-295) carries no taint sink kind — it must
    // still light up cryptographic-failure coverage via its CWE.
    const d = dossier([f({ category: "config", cwe: "CWE-295" })]);
    const top10 = buildCoverage(d, enumeratedKindsOf(d.findings), "owasp-top10");
    expect(top10.find((r) => r.id === "A02")!.state).toBe("examined");
    // And a debug-mode finding (CWE-489) lands under security misconfiguration.
    const d2 = dossier([f({ category: "config", cwe: "CWE-489" })]);
    const top10b = buildCoverage(d2, enumeratedKindsOf(d2.findings), "owasp-top10");
    expect(top10b.find((r) => r.id === "A05")!.state).toBe("examined");
  });

  it("maps weak password hashing (CWE-916) to A07, per the OWASP mapping", () => {
    // Measured on DVWA: 17 md5-password findings used to leave A07 reading
    // "not examined" while the audit had looked straight at it.
    const d = dossier([f({ category: "crypto", cwe: "CWE-916" })]);
    const rows = buildCoverage(d, enumeratedKindsOf(d.findings), "owasp-top10");
    expect(rows.find((r) => r.id === "A07")!.state).toBe("examined");
  });

  it("enumeratedKindsOf includes category, sink kind AND cwe", () => {
    const kinds = enumeratedKindsOf([f({ category: "crypto", cwe: "CWE-347", sink: { file: "a.js", line: 1, kind: "crypto" } })]);
    expect(kinds).toEqual(expect.arrayContaining(["crypto", "CWE-347"]));
  });

  it("renders the chosen standard's title in the header", () => {
    const md = renderCoverageMd(buildCoverage(dossier([]), [], "owasp-api-top10"), STANDARDS["owasp-api-top10"]!.title);
    expect(md).toMatch(/## Coverage \(OWASP API Security Top 10 \(2023\)\)/);
  });
});

describe("runCoverage — standard selection", () => {
  const silence = () => {
    const o = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    const e = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    return () => {
      o.mockRestore();
      e.mockRestore();
    };
  };

  const seed = (): string => {
    const run = mkdtempSync(join(tmpdir(), "ultrasec-cov-"));
    writeDossier(run, dossier([f({ category: "config", cwe: "CWE-489" })]));
    return run;
  };

  it("accepts every shipped standard", () => {
    const run = seed();
    const restore = silence();
    for (const id of Object.keys(STANDARDS)) {
      expect(runCoverage(parseArgs(["coverage", "--run", run, "--standard", id]))).toBe(0);
    }
    restore();
  });

  it("exit 2 on an unknown --standard instead of silently scoring ASVS", () => {
    const run = seed();
    const restore = silence();
    expect(runCoverage(parseArgs(["coverage", "--run", run, "--standard", "owasp-top-10"]))).toBe(2);
    restore();
  });
});

// ── Issue #10 (5): V7 keyed on the CWEs present, not on the pass that made them ──
// `--log-hygiene` turns on two passes with two shapes: the line-content pass
// emits `category: "logs"` + CWE-532, the taint walk emits `category: "taint"` +
// `sink.kind: "log"` + CWE-117. The matrix listed only "logs", so a real audit
// with 117 CWE-117 findings scored V7 as "not examined".
describe("V7 / A09 — logging coverage is CWE-keyed", () => {
  const logTaint = f({ category: "taint", cwe: "CWE-117", sink: { file: "a.js", line: 1, kind: "log" } });

  it("scores V7 examined from CWE-117 taint findings alone", () => {
    const rows = buildCoverage(dossier([logTaint]), enumeratedKindsOf([logTaint]));
    const v7 = rows.find((r) => r.id === "V7")!;
    expect(v7.state).toBe("examined");
    expect(v7.hits).toBe(1);
  });

  it("still scores V7 examined from the CWE-532 hygiene pass", () => {
    const hygiene = f({ category: "logs", cwe: "CWE-532", sink: { file: "a.js", line: 1, kind: "log" } });
    expect(buildCoverage(dossier([hygiene])).find((r) => r.id === "V7")!.state).toBe("examined");
  });

  it("scores OWASP A09 the same way", () => {
    const rows = buildCoverage(dossier([logTaint]), enumeratedKindsOf([logTaint]), "owasp-top10");
    expect(rows.find((r) => r.id === "A09")!.state).toBe("examined");
  });

  it("leaves V7 unexamined when nothing logging-shaped is present", () => {
    expect(buildCoverage(dossier([f({ cwe: "CWE-89" })])).find((r) => r.id === "V7")!.state).toBe("unexamined");
  });
});

// ── Issue #10 (5): "flag not passed" vs "flag passed, zero results" ───────────
describe("V7 advice distinguishes a missing flag from an empty pass", () => {
  const withPasses = (passes?: { logHygiene?: boolean }): Dossier => {
    const d = dossier([]);
    if (passes) d.manifest.passes = passes;
    return d;
  };

  it("tells you to enable --log-hygiene when the manifest doesn't say it ran", () => {
    expect(buildCoverage(withPasses()).find((r) => r.id === "V7")!.hint).toMatch(/Needs `scan --log-hygiene`/);
  });

  it("does NOT tell you to enable a flag you already passed", () => {
    const hint = buildCoverage(withPasses({ logHygiene: true })).find((r) => r.id === "V7")!.hint;
    expect(hint).not.toMatch(/Needs `scan --log-hygiene`/);
    expect(hint).toMatch(/ran and found no/);
  });

  it("keeps the old advice for a dossier written before `passes` existed", () => {
    // schemaVersion 7 dossiers omit the field entirely — undefined means
    // "unknown", never "off".
    expect(buildCoverage(withPasses({})).find((r) => r.id === "V7")!.hint).toMatch(/Needs `scan --log-hygiene`/);
  });
});
