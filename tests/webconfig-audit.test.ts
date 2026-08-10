import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { auditWebConfig, WEBCONFIG_SHAPES } from "../src/webconfig.js";

// The API/web-misconfig detector, measured the bench way: vuln/safe twins with an
// expectations map. TPR=1 (every vuln file yields EXACTLY its expected shapes) and
// FPR=0 (every safe file yields nothing). Kept OUT of tests/fixtures/bench/ so the
// "exactly 27 sink classes" contract (tests/bench.test.ts) is untouched.

const FIXTURE = join(import.meta.dirname, "fixtures", "webconfig");
const expectations = JSON.parse(readFileSync(join(FIXTURE, "expectations.json"), "utf8")) as Record<string, string[]>;

// title → shape id, so a finding's shape is recoverable from its (unique) title.
const idByTitle = new Map(Object.values(WEBCONFIG_SHAPES).map((s) => [`Web misconfig — ${s.title}`, s.id]));

const findings = auditWebConfig(FIXTURE);
const shapesByFile = new Map<string, Set<string>>();
for (const f of findings) {
  const rel = f.sink!.file;
  const id = idByTitle.get(f.title);
  if (!shapesByFile.has(rel)) shapesByFile.set(rel, new Set());
  if (id) shapesByFile.get(rel)!.add(id);
}

describe("web-misconfig audit", () => {
  it("grounds every finding on a resolvable [file:line] with category config", () => {
    for (const f of findings) {
      expect(f.category).toBe("config");
      expect(f.sink?.file).toBeTruthy();
      expect(f.sink?.line).toBeGreaterThan(0);
      expect(f.cwe).toMatch(/^CWE-\d+$/);
    }
  });

  it("each vuln twin yields EXACTLY its expected shapes (TPR=1)", () => {
    for (const [rel, expected] of Object.entries(expectations)) {
      if (expected.length === 0) continue;
      const got = [...(shapesByFile.get(rel) ?? new Set())].sort();
      expect(got, `${rel}`).toEqual([...expected].sort());
    }
  });

  it("no safe twin produces any finding (FPR=0)", () => {
    for (const [rel, expected] of Object.entries(expectations)) {
      if (expected.length > 0) continue;
      expect(shapesByFile.get(rel) ?? new Set(), `${rel} must be clean`).toEqual(new Set());
    }
  });

  it("reports on no file outside the expectations map (no stray findings)", () => {
    for (const rel of shapesByFile.keys()) {
      expect(Object.hasOwn(expectations, rel), `unexpected finding in ${rel}`).toBe(true);
    }
  });

  it("covers TLS-verify across node/python/go/php (unblocks ASVS V9 / Top10 A02)", () => {
    for (const rel of ["tls/node.js", "tls/py.py", "tls/go.go", "tls/php.php"]) {
      expect(shapesByFile.get(rel), rel).toEqual(new Set(["tls-verify"]));
    }
  });
});
