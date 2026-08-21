import { describe, it, expect } from "vitest";
import { join } from "node:path";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { classifyNoise, demoteNoise } from "../src/noise.js";
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
