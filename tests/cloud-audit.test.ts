import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { auditCloud, CLOUD_SHAPES } from "../src/cloud.js";

// WS-B: the cloud/K8s/IaC detector, measured the bench way — vuln/safe twins per
// shape with an expectations map (TPR=1 / FPR=0). Kept OUT of tests/fixtures/bench/
// so the "exactly 27 sink classes" contract is untouched (no new sink kind).

const FIXTURE = join(import.meta.dirname, "fixtures", "cloud");
const expectations = JSON.parse(readFileSync(join(FIXTURE, "expectations.json"), "utf8")) as Record<string, string[]>;

const idByTitle = new Map(Object.values(CLOUD_SHAPES).map((s) => [`Cloud/IaC — ${s.title}`, s.id]));

const findings = auditCloud(FIXTURE);
const shapesByFile = new Map<string, Set<string>>();
for (const f of findings) {
  const rel = f.sink!.file;
  const id = idByTitle.get(f.title);
  if (!shapesByFile.has(rel)) shapesByFile.set(rel, new Set());
  if (id) shapesByFile.get(rel)!.add(id);
}

describe("cloud/IaC audit", () => {
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

  it("only flags K8s security-context in files that look like manifests", () => {
    // The safe manifest has apiVersion+kind but only hardened values → clean.
    expect(shapesByFile.get("k8s/safe.yaml") ?? new Set()).toEqual(new Set());
  });

  it("reports on no file outside the expectations map (no stray findings)", () => {
    for (const rel of shapesByFile.keys()) {
      expect(Object.hasOwn(expectations, rel), `unexpected finding in ${rel}`).toBe(true);
    }
  });
});
