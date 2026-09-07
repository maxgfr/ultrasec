import { describe, it, expect, vi } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runInvestigate } from "../src/commands/investigate.js";
import { writeDossier, loadDossier, type Dossier } from "../src/store.js";
import { parseArgs } from "../src/util.js";
import type { Finding } from "../src/types.js";

// Regression cover for the second half of the `--strict` contract.
//
// `--strict` promises "exit 1 if any row was refused". A discovery can be
// refused in TWO places: the parser drops a malformed row (`parsed.dropped`),
// or `ingestDiscoveries` rejects a well-formed row whose citation doesn't
// resolve in the repo (`res.rejected`). Only the first counted toward the exit
// code, so a schema-valid discovery citing an invented [file:line] — exactly
// the failure mode the citation gate exists to catch — reported
// `rejected 1 · dropped 0` and exited 0. A CI job gating on `investigate
// --apply --strict` saw green while the finding never entered the dossier and
// no later stage would ever report it missing.
//
// `variants --apply`, the sibling stage that folds discoveries through the same
// citation gate, already counted `res.rejected` in its `--json` exit.

const REPO = join(import.meta.dirname, "fixtures", "vuln-express");

function seed(): string {
  const run = mkdtempSync(join(tmpdir(), "ultrasec-strict-reject-"));
  const f: Finding = {
    id: "f1",
    category: "taint",
    cwe: "CWE-89",
    title: "SQLi",
    severity: "high",
    confidence: "high",
    message: "m",
    tool: "ultrasec",
    status: "open",
    sink: { file: "src/db.js", line: 6 },
  };
  const d: Dossier = {
    manifest: {
      version: "0",
      schemaVersion: 5,
      repo: REPO,
      generatedNote: "",
      languages: ["javascript"],
      toolsRun: [],
      counts: { findings: 1, bySeverity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 } },
    },
    findings: [f],
    graph: { files: [], edges: [], symbolDefs: {} },
  };
  writeDossier(run, d);
  return run;
}

/** Capture stdout the way the CLI writes it (println → process.stdout.write). */
function capture(fn: () => number): { code: number; out: string } {
  const chunks: string[] = [];
  const spy = vi.spyOn(process.stdout, "write").mockImplementation((c: any) => {
    chunks.push(String(c));
    return true;
  });
  try {
    return { code: fn(), out: chunks.join("") };
  } finally {
    spy.mockRestore();
  }
}

function apply(run: string, rows: unknown[], flags: string[] = []): { code: number; out: string } {
  const file = join(run, "INVESTIGATE.json");
  writeFileSync(file, JSON.stringify(rows));
  return capture(() => runInvestigate(parseArgs(["--run", run, "--apply", file, "--repo", REPO, ...flags])));
}

/** Schema-valid in every field — refused only by the citation gate. */
const INVENTED = {
  category: "authz",
  severity: "high",
  title: "Invented authorization gap",
  message: "Deliberately invalid evidence",
  file: "not-a-real-source.js",
  line: 999,
};

/** Same shape, citing a line that really exists in the fixture. */
const GROUNDED = {
  category: "authz",
  severity: "medium",
  title: "IDOR on invoice",
  message: "no ownership check",
  file: "src/db.js",
  line: 6,
};

describe("investigate --apply --strict fails on a rejected citation, not only on a dropped row", () => {
  it("exits 1 in human mode when the only discovery was rejected for an unresolvable citation", () => {
    const run = seed();

    const { code, out } = apply(run, [INVENTED], ["--strict"]);

    expect(out).toMatch(/rejected 1 · dropped 0/);
    expect(out).toMatch(/✗ rejected "Invented authorization gap": file not found: not-a-real-source\.js/);
    expect(code).toBe(1);
    // …and it really is absent, which is why the exit code has to say so.
    expect(loadDossier(run).findings.some((f) => f.title === INVENTED.title)).toBe(false);
  });

  it("exits 1 in --json mode on the same payload, with the rejection in the report", () => {
    const run = seed();

    const { code, out } = apply(run, [INVENTED], ["--strict", "--json"]);

    const parsed = JSON.parse(out);
    expect(parsed.ingested).toBe(0);
    expect(parsed.dropped).toEqual([]);
    expect(parsed.rejected).toEqual([{ title: INVENTED.title, reason: expect.stringMatching(/file not found/) }]);
    expect(code).toBe(1);
  });

  it("keeps the usable row while still failing — a mixed batch is applied AND refused", () => {
    const run = seed();

    const { code, out } = apply(run, [GROUNDED, INVENTED], ["--strict"]);

    expect(code).toBe(1);
    expect(out).toMatch(/ingested 1 new/);
    // The valid discovery is not suppressed by the strict failure: --strict makes
    // the loss visible, it does not roll back the fold.
    expect(loadDossier(run).findings.some((f) => f.title === GROUNDED.title)).toBe(true);
  });

  it("still fails in --json mode when the batch mixes a rejection with an accepted row", () => {
    const run = seed();

    const { code, out } = apply(run, [GROUNDED, INVENTED], ["--strict", "--json"]);

    const parsed = JSON.parse(out);
    expect(parsed.ingested).toBe(1);
    expect(parsed.rejected).toHaveLength(1);
    expect(code).toBe(1);
    expect(loadDossier(run).findings.some((f) => f.title === GROUNDED.title)).toBe(true);
  });

  it("a malformed row and a rejected citation together still exit 1 (drops keep failing)", () => {
    const run = seed();

    const { code, out } = apply(run, [GROUNDED, INVENTED, { ...GROUNDED, title: "bad category", category: "banana" }], ["--strict"]);

    expect(code).toBe(1);
    expect(out).toMatch(/--strict: 1 malformed row\(s\) refused/);
    expect(out).toMatch(/✗ rejected "Invented authorization gap"/);
  });
});

describe("investigate --apply --strict stays green when nothing was refused", () => {
  it("exits 0 in human mode when every discovery was accepted", () => {
    const run = seed();

    const { code, out } = apply(run, [GROUNDED, { ...GROUNDED, title: "Missing guard", file: "src/server.js", line: 9 }], ["--strict"]);

    expect(code).toBe(0);
    expect(out).toMatch(/rejected 0 · dropped 0/);
  });

  it("exits 0 in --json mode when every discovery was accepted", () => {
    const run = seed();

    const { code, out } = apply(run, [GROUNDED], ["--strict", "--json"]);

    const parsed = JSON.parse(out);
    expect(parsed.rejected).toEqual([]);
    expect(parsed.dropped).toEqual([]);
    expect(code).toBe(0);
  });

  it("folds a duplicate location under --strict without failing — a fold is not a refusal", () => {
    // GROUNDED cites the seeded finding's exact location, so this is `folded`,
    // not `ingested`, and must stay a success.
    const run = seed();

    const { code, out } = apply(run, [{ ...GROUNDED, category: "taint", cwe: "CWE-89", title: "SQLi" }], ["--strict"]);

    expect(code).toBe(0);
    expect(out).toMatch(/folded 1 into existing/);
  });
});

describe("investigate --apply without --strict is unchanged", () => {
  it("still exits 0 on a rejected citation, and still prints why", () => {
    const run = seed();

    const { code, out } = apply(run, [INVENTED]);

    expect(code).toBe(0);
    expect(out).toMatch(/✗ rejected "Invented authorization gap": file not found/);
  });

  it("still exits 0 in --json mode on a rejected citation", () => {
    const run = seed();

    const { code, out } = apply(run, [GROUNDED, INVENTED], ["--json"]);

    const parsed = JSON.parse(out);
    expect(parsed.ingested).toBe(1);
    expect(parsed.rejected).toHaveLength(1);
    expect(code).toBe(0);
  });
});
