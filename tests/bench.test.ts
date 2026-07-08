import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { scanRepo } from "../src/scan.js";
import { buildGraph } from "../src/graph.js";
import { enumerateTaint } from "../src/taint.js";
import type { Finding } from "../src/types.js";

// Labelled per-CWE benchmark (eval P0.1). Each tests/fixtures/bench/<class>/ is a
// tiny offline corpus with an expectations.json describing its cases:
//   { cwe, cases: [{ name, file, vulnerable, crossFile? }] }
// The engine runs mechanically (scan → graph → taint, no external tools, no
// network) and we score per class:
//   TPR = detected vulnerable cases / vulnerable cases
//   FPR = safe cases with a finding on their file / safe cases
//   Youden J = TPR − FPR
// Detection = a finding of the case's CWE whose path intersects the case file
// (SATE "Path ∩ V_vul ≠ ∅"). The corpus is deterministic, so every class must
// score TPR = 1 and FPR = 0; cross-file cases must show a path spanning >1 file.

interface Case {
  name: string;
  file: string;
  vulnerable: boolean;
  crossFile?: boolean;
}
interface Expectations {
  cwe: string;
  cases: Case[];
}

const BENCH = join(import.meta.dirname, "fixtures", "bench");

function pathFiles(f: Finding): Set<string> {
  const files = new Set<string>();
  for (const p of f.path ?? []) files.add(p.file);
  if (f.sink) files.add(f.sink.file);
  return files;
}

function runClass(dir: string): Finding[] {
  const scan = scanRepo(dir);
  return enumerateTaint(scan, buildGraph(scan), { maxDepth: 8, maxCandidates: 10000 }).findings;
}

const classes = readdirSync(BENCH)
  .filter((d) => existsSync(join(BENCH, d, "expectations.json")))
  .sort();

// One scorecard row per class, printed at the end (visible under CI logs).
const scorecard: { cwe: string; tpr: number; fpr: number; youden: number; cases: number }[] = [];

describe("bench — per-CWE detection scorecard", () => {
  it("covers all 16 catalog sink classes", () => {
    expect(classes.length).toBe(16);
  });

  for (const cls of classes) {
    const dir = join(BENCH, cls);
    const exp = JSON.parse(readFileSync(join(dir, "expectations.json"), "utf8")) as Expectations;

    describe(`${cls} (${exp.cwe})`, () => {
      const findings = runClass(dir);
      const vuln = exp.cases.filter((c) => c.vulnerable);
      const safe = exp.cases.filter((c) => !c.vulnerable);

      const detected = (c: Case) => findings.filter((f) => f.cwe === exp.cwe && pathFiles(f).has(c.file));

      it("detects every vulnerable case (TPR = 1)", () => {
        for (const c of vuln) {
          expect(detected(c).length, `${cls}/${c.name}: expected a ${exp.cwe} finding intersecting ${c.file}`).toBeGreaterThan(0);
        }
      });

      it("flags no safe twin (FPR = 0)", () => {
        for (const c of safe) {
          const onFile = findings.filter((f) => pathFiles(f).has(c.file));
          expect(
            onFile.map((f) => `${f.cwe}@${f.sink?.file}:${f.sink?.line}`),
            `${cls}/${c.name}: safe twin ${c.file} must not be flagged`,
          ).toEqual([]);
        }
      });

      it("crosses a file boundary where the case is cross-file", () => {
        for (const c of vuln.filter((c) => c.crossFile)) {
          const hit = detected(c).find((f) => pathFiles(f).size > 1);
          expect(hit, `${cls}/${c.name}: expected a cross-file path for ${c.file}`).toBeTruthy();
        }
      });

      it("records the scorecard row", () => {
        const tp = vuln.filter((c) => detected(c).length > 0).length;
        const fp = safe.filter((c) => findings.some((f) => pathFiles(f).has(c.file))).length;
        const tpr = vuln.length ? tp / vuln.length : 1;
        const fpr = safe.length ? fp / safe.length : 0;
        scorecard.push({ cwe: exp.cwe, tpr, fpr, youden: tpr - fpr, cases: exp.cases.length });
        expect(tpr).toBe(1);
        expect(fpr).toBe(0);
      });
    });
  }

  it("prints the per-CWE scorecard (all classes Youden = 1)", () => {
    scorecard.sort((a, b) => a.cwe.localeCompare(b.cwe));
    const rows = scorecard.map((r) => `  ${r.cwe.padEnd(9)} TPR ${r.tpr.toFixed(2)} · FPR ${r.fpr.toFixed(2)} · J ${r.youden.toFixed(2)} · ${r.cases} cases`);
    console.log(["", "bench scorecard (per CWE class):", ...rows].join("\n"));
    expect(scorecard.every((r) => r.youden === 1)).toBe(true);
  });
});
