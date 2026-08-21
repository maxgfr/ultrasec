import { describe, it, expect } from "vitest";
import { join } from "node:path";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { classifyNoise, demoteNoise, proposalSummary, renderProposalSummary } from "../src/noise.js";
import { NOISE_GROUND, BROCARDS, type Finding } from "../src/types.js";

const FIXTURE = join(import.meta.dirname, "fixtures", "vuln-express");

function finding(over: Partial<Finding> = {}): Finding {
  return {
    id: "a",
    category: "taint",
    title: "candidate",
    severity: "high",
    confidence: "low",
    message: "candidate",
    tool: "ultrasec",
    status: "open",
    ...over,
  };
}

/** A taint finding whose every node sits where `files` say. */
function pathThrough(...files: string[]): Finding {
  return finding({
    source: { file: files[0]!, line: 1 },
    sink: { file: files[files.length - 1]!, line: 2 },
    path: files.map((f, i) => ({ file: f, line: i + 1, why: "hop" })),
  });
}

describe("test-only-path", () => {
  it("demotes a candidate whose every node is in the test harness", () => {
    const f = pathThrough("src/modules/__tests__/contributions.test.tsx", "src/modules/__tests__/helper.ts");
    expect(classifyNoise(f, FIXTURE)).toBe("test-only-path");
  });

  it("recognises the shapes the real run produced", () => {
    for (const p of ["src/e2e/contributions.e2e.ts", "src/modules/__tests__/x.test.tsx", "test/helpers.js", "spec/thing_spec.rb"]) {
      expect(classifyNoise(pathThrough(p), FIXTURE), p).toBe("test-only-path");
    }
  });

  // The rule that makes this safe. A test that drives production code is a real
  // reachability signal, and demoting it would be exactly the silent loss this
  // pass exists to avoid.
  it("does NOT demote a path with a single production node", () => {
    const f = pathThrough("src/__tests__/api.test.ts", "src/api/service.ts");
    expect(classifyNoise(f, FIXTURE)).toBeUndefined();
  });

  it("leaves a secret in a test file alone — CI tokens live there", () => {
    const f = finding({ category: "secret", sink: { file: "src/__tests__/fixtures.ts", line: 3 } });
    expect(classifyNoise(f, FIXTURE)).toBeUndefined();
  });

  it("--include-tests keeps them at full severity", () => {
    const f = pathThrough("src/__tests__/a.test.ts");
    expect(classifyNoise(f, FIXTURE, { includeTests: true })).toBeUndefined();
    expect(demoteNoise([f], FIXTURE, { includeTests: true }).downgraded).toEqual([]);
  });
});

describe("vendored-artifact", () => {
  it("demotes an entropy hit inside a vendored tool bundle", () => {
    const f = finding({ category: "secret", severity: "high", sink: { file: ".yarn/releases/yarn-3.8.7.cjs", line: 40 } });
    expect(classifyNoise(f, FIXTURE)).toBe("vendored-artifact");
  });

  it("covers minified bundles and third-party trees", () => {
    for (const p of ["public/app.min.js", "vendor/lib/thing.js", "third_party/x/y.js"]) {
      expect(classifyNoise(finding({ category: "secret", sink: { file: p, line: 1 } }), FIXTURE), p).toBe("vendored-artifact");
    }
  });

  it("does NOT demote a dependency advisory — it is keyed on the package, not the file", () => {
    const f = finding({ category: "dep", sink: { file: "vendor/pkg/package.json", line: 1 } });
    expect(classifyNoise(f, FIXTURE)).toBeUndefined();
  });

  it("does NOT demote ordinary source", () => {
    expect(classifyNoise(finding({ category: "secret", sink: { file: "src/config.ts", line: 1 } }), FIXTURE)).toBeUndefined();
  });
});

describe("pattern-declaration", () => {
  // Found by auditing ultrasec with ultrasec: `src/authtokens.ts` holds the rules
  // that detect `alg: none` and `wantAssertionsSigned: false`, and the `note:`
  // fields quoting those strings matched the rules describing them — two
  // CRITICALs on the file whose whole job is to name that bug.
  function repoWith(line: string): { repo: string; f: Finding } {
    const repo = mkdtempSync(join(tmpdir(), "usec-decl-"));
    writeFileSync(join(repo, "rules.ts"), `const RULES = [\n${line}\n];\n`);
    return { repo, f: finding({ category: "crypto", severity: "critical", sink: { file: "rules.ts", line: 2 } }) };
  }

  it("demotes a rule-metadata line that quotes the pattern it warns about", () => {
    const { repo, f } = repoWith('  note: "`wantAssertionsSigned: false` accepts an unsigned assertion",');
    expect(classifyNoise(f, repo)).toBe("pattern-declaration");
  });

  it("demotes a bare regex-literal line", () => {
    const { repo, f } = repoWith("  /alg\\s*:\\s*['\"]none['\"]/,");
    expect(classifyNoise(f, repo)).toBe("pattern-declaration");
  });

  it("covers the metadata property names rule packs actually use", () => {
    for (const prop of ["re", "pattern", "description", "remediation", "example", "title"]) {
      const { repo, f } = repoWith(`  ${prop}: "alg: none",`);
      expect(classifyNoise(f, repo), prop).toBe("pattern-declaration");
    }
  });

  // The false-negative guard: only the line's FIRST property counts, so real
  // configuration is never mistaken for documentation about configuration.
  it("demotes a whole-line comment describing the pattern", () => {
    const { repo, f } = repoWith("  // jwt.verify(...) that never pins `algorithms` — the key-confusion enabler.");
    expect(classifyNoise(f, repo)).toBe("pattern-declaration");
  });

  it("does NOT demote a statement that merely carries a trailing comment", () => {
    const { repo, f } = repoWith("  rejectUnauthorized: false, // TODO");
    expect(classifyNoise(f, repo)).toBeUndefined();
  });

  it("does NOT demote real configuration that happens to use those values", () => {
    const { repo, f } = repoWith('  algorithms: ["none"],');
    expect(classifyNoise(f, repo)).toBeUndefined();
  });

  it("does NOT demote a plain dangerous statement", () => {
    const { repo, f } = repoWith("  rejectUnauthorized: false,");
    expect(classifyNoise(f, repo)).toBeUndefined();
  });

  it("does NOT demote a dependency advisory", () => {
    const { repo } = repoWith('  note: "alg: none",');
    const dep = finding({ category: "dep", sink: { file: "rules.ts", line: 2 } });
    expect(classifyNoise(dep, repo)).toBeUndefined();
  });

  it("treats an unreadable file as ordinary code, never as suppressed", () => {
    const f = finding({ category: "crypto", sink: { file: "does-not-exist.ts", line: 1 } });
    expect(classifyNoise(f, FIXTURE)).toBeUndefined();
  });
});

describe("resource-identifier", () => {
  // `const SPREADSHEET_KEY = "1a2b…"` is a Google Sheets document id. gitleaks
  // rates it a Generic API Key on entropy — helped by the word KEY in the name —
  // but holding a document id is not holding access to the document. Seven of
  // the 37 false positives on the first real audit were exactly this.
  function repoWith(line: string) {
    const repo = mkdtempSync(join(tmpdir(), "usec-resid-"));
    writeFileSync(join(repo, "cfg.js"), `// header\n${line}\n`);
    return { repo, f: finding({ category: "secret", severity: "high", sink: { file: "cfg.js", line: 2 } }) };
  }

  it("demotes a document id whose NAME says what it is", () => {
    const { repo, f } = repoWith('const SPREADSHEET_KEY = "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms";');
    expect(classifyNoise(f, repo)).toBe("resource-identifier");
  });

  it("covers the resource-id names that actually occur", () => {
    for (const name of ["SHEET_ID", "DOCUMENT_ID", "FOLDER_ID", "PROJECT_ID", "BUCKET_ID", "CALENDAR_ID"]) {
      const { repo, f } = repoWith(`const ${name} = "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74Og";`);
      expect(classifyNoise(f, repo), name).toBe("resource-identifier");
    }
  });

  // The two guards that make the claim narrow enough to be true.
  it("does NOT demote on the word KEY alone — that is what made gitleaks fire", () => {
    const { repo, f } = repoWith('const API_KEY = "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74Og";');
    expect(classifyNoise(f, repo)).toBeUndefined();
  });

  it("does NOT demote a real credential in a badly-named variable", () => {
    for (const value of [
      "-----BEGIN RSA PRIVATE KEY-----",
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
      "AKIAIOSFODNN7EXAMPLE",
      "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
      "AIzaSyD-1234567890abcdefghijklmnopqrstuv",
    ]) {
      const { repo, f } = repoWith(`const SPREADSHEET_KEY = "${value}";`);
      expect(classifyNoise(f, repo), value.slice(0, 12)).toBeUndefined();
    }
  });

  it("only applies to secret findings", () => {
    const { repo } = repoWith('const SHEET_ID = "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74Og";');
    const taint = finding({ category: "taint", sink: { file: "cfg.js", line: 2 } });
    expect(classifyNoise(taint, repo)).toBeUndefined();
  });

  it("lands at low, not info — it still deserves a glance", () => {
    const { repo, f } = repoWith('const SHEET_ID = "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74Og";');
    const out = demoteNoise([f], repo).findings[0]!;
    expect(out.severity).toBe("low");
    expect(out.message).toMatch(/CHECK the document's sharing setting/);
  });
});

describe("verified credentials are never demoted", () => {
  // A live credential is live, whatever the file it sits in claims to be.
  it("overrides every class", () => {
    const f = finding({ category: "secret", verified: true, sink: { file: ".yarn/releases/yarn-3.8.7.cjs", line: 1 } });
    expect(classifyNoise(f, FIXTURE)).toBeUndefined();
  });
});

describe("demoteNoise — demote, never drop, always account", () => {
  it("keeps every finding and reports a count per class", () => {
    const input = [
      pathThrough("src/__tests__/a.test.ts"),
      finding({ id: "b", category: "secret", sink: { file: ".yarn/releases/yarn-3.8.7.cjs", line: 1 } }),
      finding({ id: "c", sink: { file: "src/real.ts", line: 1 } }),
    ];
    const { findings, downgraded } = demoteNoise(input, FIXTURE);
    // Nothing disappears — the report is re-ordered, not shortened.
    expect(findings).toHaveLength(3);
    expect(downgraded).toEqual([
      { reason: "test-only-path", count: 1 },
      { reason: "vendored-artifact", count: 1 },
    ]);
    expect(findings.find((f) => f.id === "c")!.severity).toBe("high");
    expect(findings.find((f) => f.id === "c")!.noise).toBeUndefined();
  });

  it("names the reason in the message so the demotion can be interrogated", () => {
    const { findings } = demoteNoise([pathThrough("src/__tests__/a.test.ts")], FIXTURE);
    expect(findings[0]!.message).toMatch(/every cited location is a test path/);
    expect(findings[0]!.noise).toBe("test-only-path");
  });

  it("never sets a status, a verdict or a brocard — demotion is not adjudication", () => {
    const { findings } = demoteNoise([pathThrough("src/__tests__/a.test.ts")], FIXTURE);
    expect(findings[0]!.status).toBe("open");
    expect(findings[0]!.verdict).toBeUndefined();
    expect(findings[0]!.brocard).toBeUndefined();
  });

  it("floors the severity and never raises it", () => {
    const already = finding({ severity: "info", source: { file: "src/__tests__/a.test.ts", line: 1 }, sink: { file: "src/__tests__/a.test.ts", line: 2 } });
    expect(demoteNoise([already], FIXTURE).findings[0]!.severity).toBe("info");
  });

  it("is a no-op on a clean finding set", () => {
    const input = [finding({ sink: { file: "src/real.ts", line: 1 } })];
    const { findings, downgraded } = demoteNoise(input, FIXTURE);
    expect(downgraded).toEqual([]);
    expect(findings[0]).toEqual(input[0]);
  });
});

describe("NOISE_GROUND", () => {
  // The table is the argument: a reviewer disagrees with a row here rather than
  // with a new, unfalsifiable ground invented for the occasion.
  it("maps every class onto an EXISTING brocard", () => {
    for (const [cls, ground] of Object.entries(NOISE_GROUND)) {
      expect(BROCARDS as readonly string[], cls).toContain(ground);
    }
  });
});

describe("proposalSummary — the only grouping this design does", () => {
  // Grouping saves no VERDICT (`check --semantic` counts per finding) and must
  // not try to: a group that fanned out would let one row rewrite findings the
  // apply file never named. What it saves is READING — 46 identical
  // "every node of this path is a test path" lines bury the items needing thought.
  const items = [
    { id: "aaa", proposed: { class: "test-only-path" as const, ground: "outside-usage" as const, why: "w1" } },
    { id: "bbb", proposed: { class: "test-only-path" as const, ground: "outside-usage" as const, why: "w1" } },
    { id: "ccc", proposed: { class: "vendored-artifact" as const, ground: "no-threat-model" as const, why: "w2" } },
    { id: "ddd" },
  ];

  it("names each class once, with its ground and its members", () => {
    expect(proposalSummary(items)).toEqual([
      { class: "test-only-path", ground: "outside-usage", why: "w1", ids: ["aaa", "bbb"] },
      { class: "vendored-artifact", ground: "no-threat-model", why: "w2", ids: ["ccc"] },
    ]);
  });

  it("renders a block that states it is a suggestion, not an adjudication", () => {
    const md = renderProposalSummary(items).join("\n");
    expect(md).toContain("## Proposed noise classes (2)");
    expect(md).toContain("**test-only-path** (2)");
    expect(md).toContain("`outside-usage`");
    expect(md).toMatch(/did not\s+adjudicate them/);
  });

  it("caps the id list so a large family does not reprint the worklist", () => {
    const many = Array.from({ length: 40 }, (_, i) => ({
      id: `id${i}`,
      proposed: { class: "test-only-path" as const, ground: "outside-usage" as const, why: "w" },
    }));
    expect(renderProposalSummary(many).join("\n")).toContain("and 32 more");
  });

  it("renders nothing when nothing was classified — the block is presence-gated", () => {
    expect(renderProposalSummary([{ id: "x" }])).toEqual([]);
    expect(proposalSummary([{ id: "x" }])).toEqual([]);
  });
});
