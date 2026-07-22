import { describe, it, expect } from "vitest";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { scanRepo, type ScanOptions } from "../src/scan.js";
import { buildGraph } from "../src/graph.js";
import { enumerateTaint } from "../src/taint.js";
import { enumerateSinkCandidates } from "../src/sinks.js";
import { correlate } from "../src/tools/correlate.js";
import { enrichFindings } from "../src/tools/scoring.js";

// ── Golden finding-set + graph snapshots ─────────────────────────────────────
// The engine's load-bearing artifact is the FULL deterministic finding set (the
// taint + orphan-sink pipeline, external tools and network enrichment off) and
// the graph.json feeding it. These snapshots freeze both over every vulnerable
// fixture BEFORE the codeindex-engine migration; any behavioural drift in the
// walker/extractor/resolver/graph must surface here as a diff and be adjudicated
// explicitly — never silently.
//
// Regenerate deliberately with: UPDATE_GOLDEN=1 pnpm test golden-findings

const FIXTURES = join(import.meta.dirname, "fixtures");
const GOLDEN = join(import.meta.dirname, "golden");
const BENCH = join(FIXTURES, "bench");

interface GoldenCase {
  name: string;
  dir: string;
  opts?: ScanOptions;
}

const cases: GoldenCase[] = [
  { name: "vuln-express", dir: join(FIXTURES, "vuln-express") },
  { name: "vuln-extra", dir: join(FIXTURES, "vuln-extra") },
  // The 3-file-chain fixture, with and without gitignore honouring: the scratch/
  // tree carries a fake finding that must exist by default and vanish under
  // `--gitignore`.
  { name: "vuln-chain", dir: join(FIXTURES, "vuln-chain") },
  { name: "vuln-chain-gitignore", dir: join(FIXTURES, "vuln-chain"), opts: { gitignore: true } },
  ...readdirSync(BENCH)
    .filter((d) => existsSync(join(BENCH, d, "expectations.json")))
    .sort()
    .map((d) => ({ name: `bench-${d}`, dir: join(BENCH, d) })),
];

/** The deterministic scan pipeline: scan → graph → taint → orphan sinks →
 *  correlate → severity-only risk (external tools and feeds excluded). */
async function runPipeline(dir: string, opts: ScanOptions = {}) {
  const scan = scanRepo(dir, opts);
  const graph = buildGraph(scan);
  const taint = enumerateTaint(scan, graph);
  const sinks = enumerateSinkCandidates(scan, taint.findings);
  const merged = correlate([...taint.findings, ...sinks.findings]);
  const { findings } = await enrichFindings(merged, { enabled: false });
  return { findings, graph };
}

const UPDATE = !!process.env.UPDATE_GOLDEN;

describe("golden — full deterministic finding set and graph per fixture", () => {
  for (const c of cases) {
    it(`${c.name}: findings and graph match the committed golden`, async () => {
      const { findings, graph } = await runPipeline(c.dir, c.opts);
      const actual = JSON.stringify({ findings, graph }, null, 2) + "\n";
      const file = join(GOLDEN, `${c.name}.json`);
      if (UPDATE) {
        mkdirSync(GOLDEN, { recursive: true });
        writeFileSync(file, actual);
        return;
      }
      expect(existsSync(file), `missing golden ${file} — run UPDATE_GOLDEN=1 pnpm test golden-findings`).toBe(true);
      expect(JSON.parse(actual)).toEqual(JSON.parse(readFileSync(file, "utf8")));
    });
  }

  it("vuln-chain: the SQLi path crosses three files", async () => {
    const { findings } = await runPipeline(join(FIXTURES, "vuln-chain"));
    const sqli = findings.find((f) => f.cwe === "CWE-89");
    expect(sqli, "expected a CWE-89 finding").toBeTruthy();
    const files = new Set((sqli!.path ?? []).map((p) => p.file));
    expect(files.size).toBeGreaterThanOrEqual(3);
  });

  it("vuln-chain: gitignore honouring drops the scratch/ finding (and only that)", async () => {
    const dir = join(FIXTURES, "vuln-chain");
    const dflt = await runPipeline(dir);
    const gi = await runPipeline(dir, { gitignore: true });
    const inScratch = (f: { path?: { file: string }[] }) => (f.path ?? []).some((p) => p.file.startsWith("scratch/"));
    expect(dflt.findings.some(inScratch), "default scan must see the scratch/ finding").toBe(true);
    expect(gi.findings.some(inScratch), "gitignore scan must not see scratch/").toBe(false);
    // Everything outside scratch/ is identical between the two modes.
    expect(dflt.findings.filter((f) => !inScratch(f))).toEqual(gi.findings);
  });

  it("vuln-chain: the receiver-gated SSRF sink fires on axios.get, never on the bare get()", async () => {
    const { findings } = await runPipeline(join(FIXTURES, "vuln-chain"));
    const ssrf = findings.filter((f) => f.cwe === "CWE-918");
    expect(ssrf.length).toBeGreaterThanOrEqual(1);
    for (const f of ssrf) expect(f.sink!.file).toBe("src/fetcher.js");
  });
});
