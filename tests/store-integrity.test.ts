import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadDossier } from "../src/store.js";

const dirs: string[] = [];
function fixture(findings: unknown): string {
  const dir = mkdtempSync(join(tmpdir(), "ultrasec-integrity-"));
  dirs.push(dir);
  writeFileSync(join(dir, "manifest.json"), "{}");
  writeFileSync(join(dir, "graph.json"), "{}");
  writeFileSync(join(dir, "findings.json"), JSON.stringify(findings));
  return dir;
}
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});
describe("persisted finding identity", () => {
  it("preserves unique IDs and accepts an empty scan", () => {
    expect(loadDossier(fixture([])).findings).toEqual([]);
    expect(loadDossier(fixture([{ id: "f1" }, { id: "f2" }])).findings.map((f) => f.id)).toEqual(["f1", "f2"]);
  });
  it.each([null, {}, [null], [{}], [{ id: " " }], [{ id: "f1" }, { id: "f1" }]].map((value) => ({ value })))(
    "rejects malformed or ambiguous finding identities: $value",
    ({ value }) => {
      expect(() => loadDossier(fixture(value))).toThrow(/findings\.json/);
    },
  );
});
