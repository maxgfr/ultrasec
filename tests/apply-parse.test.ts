import { describe, it, expect, vi } from "vitest";
import { mkdtempSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { runInvestigate } from "../src/commands/investigate.js";
import { runVerify } from "../src/commands/verify.js";
import { writeDossier, loadDossier, type Dossier } from "../src/store.js";
import { parseArgs } from "../src/util.js";
import { surfaceDropped, formatDropped } from "../src/apply-parse.js";
import type { Finding } from "../src/types.js";

// Regression cover for the silent-drop bug: before this, a `--apply` file whose
// rows were PARTIALLY valid ingested the good ones and discarded the rest with
// NO diagnostic at all — `ingested 1 · folded 0 · rejected 0` while five
// discoveries evaporated. In a tool that promises fail-closed adjudication, a
// dropped `supported` verdict silently removes a CONFIRMED vulnerability from
// the report. Every assertion below exists to keep that from coming back.

const REPO = join(import.meta.dirname, "fixtures", "vuln-express");

function seed(): string {
  const run = mkdtempSync(join(tmpdir(), "ultrasec-apply-"));
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
    graph: { files: [], symbols: [], links: [] },
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

const GOOD_DISCOVERY = {
  title: "IDOR on invoice",
  category: "authz",
  severity: "medium",
  message: "no ownership check",
  file: "src/db.js",
  line: 6,
};

describe("investigate --apply surfaces every refused row instead of dropping it", () => {
  it("ingests the valid rows AND names each invalid one, with its field and value", () => {
    const run = seed();
    const file = join(run, "INVESTIGATE.json");
    writeFileSync(
      file,
      JSON.stringify([
        GOOD_DISCOVERY,
        { ...GOOD_DISCOVERY, title: "bad category", category: "ssrf" },
        { ...GOOD_DISCOVERY, title: "bad severity", severity: "catastrophic" },
        { ...GOOD_DISCOVERY, title: "no line", line: undefined },
      ]),
    );

    const { code, out } = capture(() => runInvestigate(parseArgs(["--run", run, "--apply", file, "--repo", REPO])));

    expect(code).toBe(0);
    expect(out).toMatch(/ingested 1 new/);
    expect(out).toMatch(/dropped 3/);
    // The reason must name BOTH the field and the value received — "invalid row"
    // would leave the author bisecting the file.
    expect(out).toMatch(/row 1: category "ssrf" is not one of/);
    expect(out).toMatch(/row 2: severity "catastrophic" is not one of/);
    expect(out).toMatch(/row 3: line missing — expected an integer ≥ 1/);
    // …and the valid one really landed.
    expect(loadDossier(run).findings.some((f) => f.title === "IDOR on invoice")).toBe(true);
  });

  it("--strict turns a partial fold into a failure so CI can refuse it", () => {
    const run = seed();
    const file = join(run, "INVESTIGATE.json");
    writeFileSync(file, JSON.stringify([GOOD_DISCOVERY, { ...GOOD_DISCOVERY, category: "nope" }]));

    const { code, out } = capture(() => runInvestigate(parseArgs(["--run", run, "--apply", file, "--repo", REPO, "--strict"])));

    expect(code).toBe(1);
    expect(out).toMatch(/--strict: 1 malformed row\(s\) refused/);
    // Still not destructive: the valid row was applied, the loss is just visible.
    expect(loadDossier(run).findings.some((f) => f.title === "IDOR on invoice")).toBe(true);
  });

  it("reports dropped rows in --json so an orchestrator can act on them", () => {
    const run = seed();
    const file = join(run, "INVESTIGATE.json");
    writeFileSync(file, JSON.stringify([GOOD_DISCOVERY, { ...GOOD_DISCOVERY, severity: "nope" }]));

    const { out } = capture(() => runInvestigate(parseArgs(["--run", run, "--apply", file, "--repo", REPO, "--json"])));

    const parsed = JSON.parse(out);
    expect(parsed.ingested).toBe(1);
    expect(parsed.dropped).toHaveLength(1);
    expect(parsed.dropped[0].index).toBe(1);
    expect(parsed.dropped[0].reason).toMatch(/severity/);
  });

  it("still fails closed (exit 2) when NOTHING in the file is usable", () => {
    const run = seed();
    const file = join(run, "INVESTIGATE.json");
    writeFileSync(file, JSON.stringify([{ ...GOOD_DISCOVERY, category: "nope" }]));

    const code = runInvestigate(parseArgs(["--run", run, "--apply", file, "--repo", REPO]));
    expect(code).toBe(2);
  });
});

describe("verify --apply", () => {
  it("names the offending verdict value rather than swallowing the row", () => {
    const run = seed();
    const file = join(run, "verdicts.json");
    writeFileSync(file, JSON.stringify([{ id: "f1", verdict: "supported" }, { id: "f1", verdict: "SUPPORTED" }, { verdict: "refuted" }]));

    const { code, out } = capture(() => runVerify(parseArgs(["--run", run, "--apply", file])));

    expect(code).toBe(0);
    expect(out).toMatch(/row 1: verdict "SUPPORTED" is not one of/);
    expect(out).toMatch(/row 2: id missing/);
    expect(loadDossier(run).findings[0]!.status).toBe("confirmed");
  });
});

// `--apply -` reads fd 0, which only exists meaningfully in a real process — so
// this one runs against the built bundle with a piped stdin, the way a user
// would actually do `… | ultrasec verify --apply -`.
describe("--apply - reads stdin", () => {
  const bundle = join(import.meta.dirname, "..", "scripts", "ultrasec.mjs");

  it.runIf(existsSync(bundle))("is equivalent to passing the same content as a file", () => {
    const run = seed();
    const payload = JSON.stringify([{ id: "f1", verdict: "refuted", note: "piped" }]);

    const out = execFileSync(process.execPath, [bundle, "verify", "--run", run, "--apply", "-"], { encoding: "utf8", input: payload });

    expect(out).toMatch(/applied 1 verdict/);
    expect(loadDossier(run).findings[0]!.status).toBe("dismissed");
  });

  it.runIf(existsSync(bundle))("applies the same drop diagnostics to a piped payload", () => {
    const run = seed();
    const payload = JSON.stringify([
      { id: "f1", verdict: "refuted" },
      { id: "f1", verdict: "nope" },
    ]);

    const out = execFileSync(process.execPath, [bundle, "verify", "--run", run, "--apply", "-"], { encoding: "utf8", input: payload });

    expect(out).toMatch(/row 1: verdict "nope" is not one of/);
  });
});

describe("formatting helpers", () => {
  it("formatDropped qualifies by file only when a multi-file fold provided one", () => {
    expect(formatDropped([{ index: 2, reason: "boom" }])).toEqual(["  ✗ dropped row 2: boom"]);
    expect(formatDropped([{ index: 0, reason: "boom", file: "a.json" }])).toEqual(["  ✗ dropped a.json row 0: boom"]);
  });

  it("surfaceDropped is silent and green when nothing was refused", () => {
    const lines: string[] = [];
    expect(surfaceDropped([], true, (l) => lines.push(l))).toBe(0);
    expect(lines).toEqual([]);
  });
});
