import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { auditAuthTokens, AUTH_SHAPES } from "../src/authtokens.js";

// The auth-token detector, measured the bench way: vuln/safe twins per shape and
// per stack, with an expectations map. TPR=1 / FPR=0. Kept OUT of
// tests/fixtures/bench/ so the "exactly 27 sink classes" contract is untouched.

const FIXTURE = join(import.meta.dirname, "fixtures", "authtokens");
const expectations = JSON.parse(readFileSync(join(FIXTURE, "expectations.json"), "utf8")) as Record<string, string[]>;

const idByTitle = new Map(Object.values(AUTH_SHAPES).map((s) => [`Auth token — ${s.title}`, s.id]));

const findings = auditAuthTokens(FIXTURE);
const shapesByFile = new Map<string, Set<string>>();
for (const f of findings) {
  const rel = f.sink!.file;
  const id = idByTitle.get(f.title);
  if (!shapesByFile.has(rel)) shapesByFile.set(rel, new Set());
  if (id) shapesByFile.get(rel)!.add(id);
}

describe("auth-token audit", () => {
  it("grounds every finding on a resolvable [file:line] with category crypto|authz", () => {
    for (const f of findings) {
      expect(["crypto", "authz"]).toContain(f.category);
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

  it("does NOT flag PyJWT decode, which verifies by default (a real false-positive trap)", () => {
    expect(shapesByFile.get("jwt/safe.py") ?? new Set()).toEqual(new Set());
  });

  it("reports on no file outside the expectations map (no stray findings)", () => {
    for (const rel of shapesByFile.keys()) {
      expect(Object.hasOwn(expectations, rel), `unexpected finding in ${rel}`).toBe(true);
    }
  });
});
