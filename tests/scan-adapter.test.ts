import { describe, it, expect, afterAll } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanRepo } from "../src/scan.js";

// Covers two walk-surface regressions the engine-adoption swap (eac6b8e) introduced
// vs. the old src/walk.ts: the byte cap silently dropped from 1.5MB to the engine's
// bare 1MB default, and the `.ultrasec` dossier dir was no longer excluded from the
// walk (the engine only knows its own `.ultraindex`).

describe("scanRepo: pre-adoption byte-cap preserved", () => {
  const repo = mkdtempSync(join(tmpdir(), "ultrasec-bytecap-"));
  afterAll(() => rmSync(repo, { recursive: true, force: true }));

  // A file strictly between 1MB (the engine's bare default) and 1.5MB (ultrasec's
  // historical MAX_FILE_BYTES) — scanned before adoption, would be silently dropped
  // under the engine's own default.
  const FILLER_LINE = "// " + "x".repeat(70) + "\n"; // ~74 bytes
  let content = "function bigFile() { return 1; }\n";
  while (Buffer.byteLength(content, "utf8") < 1_200_000) content += FILLER_LINE;
  mkdirSync(repo, { recursive: true });
  writeFileSync(join(repo, "big.js"), content);
  writeFileSync(join(repo, "small.js"), "function small() { return 2; }\n");

  it("the fixture file really is between 1MB and 1.5MB (sanity-check the test itself)", () => {
    const bytes = statSync(join(repo, "big.js")).size;
    expect(bytes).toBeGreaterThan(1_000_000);
    expect(bytes).toBeLessThanOrEqual(1_500_000);
  });

  it("a 1MB-1.5MB file is still scanned (it would be dropped under the engine's bare 1MB default)", () => {
    const scan = scanRepo(repo);
    const rels = scan.files.map((f) => f.rel);
    expect(rels).toContain("big.js");
    expect(rels).toContain("small.js");
  });

  it("an explicit maxBytes still overrides the default", () => {
    const scan = scanRepo(repo, { maxBytes: 10 });
    expect(scan.files.map((f) => f.rel)).not.toContain("big.js");
    expect(scan.files.map((f) => f.rel)).not.toContain("small.js");
  });
});

describe("scanRepo: dossier dir (.ultrasec) excluded", () => {
  const repo = mkdtempSync(join(tmpdir(), "ultrasec-dossierdir-"));
  afterAll(() => rmSync(repo, { recursive: true, force: true }));

  mkdirSync(join(repo, ".ultrasec"), { recursive: true });
  writeFileSync(join(repo, ".ultrasec", "foo.js"), "function planted() { return 1; }\n");
  writeFileSync(join(repo, "real.js"), "function real() { return 2; }\n");

  it("does not scan a planted .ultrasec/foo.js (self-index guard)", () => {
    const scan = scanRepo(repo);
    const rels = scan.files.map((f) => f.rel);
    expect(rels).not.toContain(".ultrasec/foo.js");
    expect(rels).toContain("real.js");
  });
});
