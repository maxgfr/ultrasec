#!/usr/bin/env node
// Score the engine against PUBLIC, third-party labelled corpora and publish the
// numbers.
//
// tests/fixtures/bench/ is a good regression gate and a bad claim: the fixtures
// were written by the same people who wrote the rules, so a perfect score there
// proves the rules did not change, not that they are good. Nobody in this space
// publishes a number against a corpus they did not author. This does.
//
// Corpora are fetched ON DEMAND into the cache and never vendored — OWASP
// Benchmark is GPL-2.0 and this repo is MIT, so a copy in-tree would relicense
// it. That also means this script needs the network and is deliberately NOT part
// of `pnpm test`: run it before a release, commit docs/BENCHMARK.md.
//
//   node scripts/bench-public.mjs [--corpus owasp|juliet-c|all] [--limit N] [--write]
//
// Pure Node, no deps.
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const engine = join(root, "scripts", "ultrasec.mjs");
const cacheRoot = join(process.env.ULTRASEC_CACHE_DIR || join(homedir(), ".cache", "ultrasec"), "bench-public");

const args = process.argv.slice(2);
const flag = (n, d) => {
  const i = args.indexOf(`--${n}`);
  return i >= 0 && args[i + 1] && !args[i + 1].startsWith("--") ? args[i + 1] : d;
};
const has = (n) => args.includes(`--${n}`);

// ── Corpora ─────────────────────────────────────────────────────────────────
// Each declares how to fetch it and how to read its ground truth. Both shipped
// corpora label per-FILE, which is what the scorer needs and all it claims.
const CORPORA = {
  owasp: {
    title: "OWASP Benchmark v1.2 (Java)",
    license: "GPL-2.0 — fetched, never vendored",
    url: "https://github.com/OWASP-Benchmark/BenchmarkJava",
    ref: "master",
    // Ground truth ships as a CSV: name, category, real vulnerability, cwe.
    truth(dir) {
      const csv = join(dir, "expectedresults-1.2.csv");
      if (!existsSync(csv)) return null;
      const out = [];
      for (const line of readFileSync(csv, "utf8").split("\n").slice(1)) {
        const [name, , real, cwe] = line.split(",");
        if (!name?.startsWith("BenchmarkTest")) continue;
        out.push({
          file: `src/main/java/org/owasp/benchmark/testcode/${name.trim()}.java`,
          vulnerable: String(real).trim().toLowerCase() === "true",
          cwe: `CWE-${String(cwe).trim()}`,
        });
      }
      return out;
    },
  },
  "juliet-c": {
    title: "NIST Juliet 1.3 (C/C++)",
    license: "public domain",
    url: "https://samate.nist.gov/SARD/test-suites/112",
    ref: null, // not a git repo — see fetch()
    truth(dir) {
      // Juliet encodes the label in the FILENAME: `_bad` is the flawed variant,
      // `_good*` the fixed twin of the same CWE.
      const out = [];
      const walk = (d) => {
        for (const e of readdirSync(d, { withFileTypes: true })) {
          const p = join(d, e.name);
          if (e.isDirectory()) walk(p);
          else if (/\.(c|cpp)$/.test(e.name)) {
            const m = /^CWE(\d+)_/.exec(e.name);
            if (!m) continue;
            out.push({ file: relative(dir, p), vulnerable: /_bad|bad\./.test(e.name), cwe: `CWE-${m[1]}` });
          }
        }
      };
      walk(dir);
      return out;
    },
  },
};

function fetchCorpus(key) {
  const spec = CORPORA[key];
  const dir = join(cacheRoot, key);
  if (existsSync(join(dir, ".fetched"))) return dir;
  if (!spec.ref) {
    console.error(`\n${key}: no automated fetch (${spec.url} is a download, not a git repo).`);
    console.error(`Unpack it to ${dir} and create ${join(dir, ".fetched")}, then re-run.`);
    return null;
  }
  mkdirSync(dirname(dir), { recursive: true });
  console.error(`fetching ${spec.title} → ${dir} …`);
  try {
    execFileSync("git", ["clone", "--depth", "1", "--branch", spec.ref, spec.url, dir], { stdio: ["ignore", "ignore", "inherit"] });
    writeFileSync(join(dir, ".fetched"), new Date().toISOString());
    return dir;
  } catch (e) {
    console.error(`${key}: clone failed (${e.message}). Network required; nothing was scored.`);
    return null;
  }
}

// ── Scoring ─────────────────────────────────────────────────────────────────
// Detection follows the SATE convention already used by tests/bench.test.ts: a
// case is detected when a finding OF ITS CWE has a path intersecting its file.
function scoreCorpus(key, dir, limit) {
  const cases = CORPORA[key].truth(dir);
  if (!cases) return null;
  const scoped = limit ? cases.slice(0, limit) : cases;

  const out = join(cacheRoot, `${key}.run`);
  console.error(`scanning ${scoped.length} case(s) …`);
  execFileSync(
    "node",
    [engine, "scan", "--repo", dir, "--out", out, "--offline", "--no-tools", "--budget", "thorough", "--max-candidates", "200000", "--no-journal"],
    { stdio: ["ignore", "ignore", "inherit"] },
  );
  const findings = JSON.parse(readFileSync(join(out, "findings.json"), "utf8"));

  const filesByCwe = new Map();
  // Which of those the engine ALSO annotated with a sanitizer on the path. This
  // matters for reading the FPR: ultrasec is recall-oriented by design — a
  // sanitizer lowers confidence and annotates, it never auto-dismisses — so a
  // "false positive" the engine handed over WITH the mitigating evidence
  // attached is a different thing from one it reported silently.
  const sanitizedByCwe = new Map();
  for (const f of findings) {
    if (!f.cwe) continue;
    const files = new Set([...(f.path ?? []).map((p) => p.file), f.sink?.file].filter(Boolean));
    const set = filesByCwe.get(f.cwe) ?? filesByCwe.set(f.cwe, new Set()).get(f.cwe);
    const san = sanitizedByCwe.get(f.cwe) ?? sanitizedByCwe.set(f.cwe, new Set()).get(f.cwe);
    for (const x of files) {
      set.add(x);
      if (/Possible sanitizer along the path/.test(f.message ?? "")) san.add(x);
    }
  }

  const byCwe = new Map();
  for (const c of scoped) {
    const row = byCwe.get(c.cwe) ?? byCwe.set(c.cwe, { tp: 0, fn: 0, fp: 0, tn: 0, fpFlagged: 0 }).get(c.cwe);
    const detected = filesByCwe.get(c.cwe)?.has(c.file) ?? false;
    if (c.vulnerable) detected ? row.tp++ : row.fn++;
    else if (detected) {
      row.fp++;
      if (sanitizedByCwe.get(c.cwe)?.has(c.file)) row.fpFlagged++;
    } else row.tn++;
  }

  const rows = [...byCwe.entries()]
    .map(([cwe, r]) => {
      const tpr = r.tp + r.fn ? r.tp / (r.tp + r.fn) : 0;
      const fpr = r.fp + r.tn ? r.fp / (r.fp + r.tn) : 0;
      const prec = r.tp + r.fp ? r.tp / (r.tp + r.fp) : 0;
      const f1 = prec + tpr ? (2 * prec * tpr) / (prec + tpr) : 0;
      return { cwe, ...r, tpr, fpr, youden: tpr - fpr, f1 };
    })
    .sort((a, b) => a.cwe.localeCompare(b.cwe));
  return { rows, cases: scoped.length };
}

// ── Report ──────────────────────────────────────────────────────────────────
function render(results, meta) {
  const pct = (x) => (x * 100).toFixed(1).padStart(5) + "%";
  const L = [
    "# Detection, measured",
    "",
    "Scores against **third-party labelled corpora** — not the fixtures in this repo.",
    "`tests/fixtures/bench/` is a regression gate written by the same people who wrote the",
    "rules, so a perfect score there proves the rules did not change, not that they are good.",
    "These are the numbers that can be checked by someone who does not trust us.",
    "",
    `Engine \`${meta.version}\` · extraction tier \`${meta.tier}\` · generated ${meta.date}`,
    "",
    "Detection follows the SATE convention: a case counts as detected when a finding **of its",
    "CWE** has a path intersecting the case file.",
    "",
    "**Read TPR as the headline and FPR with care.** ultrasec enumerates *candidates* for a human",
    "to adjudicate: a sanitizer lowers a candidate's confidence and annotates it, it never",
    "auto-dismisses. So every sanitized-but-reported case counts against FPR here even though",
    "surfacing it is the intended behaviour — the `FP w/ sanitizer noted` column shows how many",
    "of those the engine handed over *with the mitigating evidence already attached*. A tool that",
    "auto-suppressed them would score better on this table and lose real bugs, which is the",
    "trade this project has deliberately not made.",
    "",
  ];
  for (const [key, res] of Object.entries(results)) {
    const spec = CORPORA[key];
    L.push(`## ${spec.title}`, "", `${res.cases} cases · ${spec.license} · <${spec.url}>`, "");
    L.push("| CWE | TP | FN | FP | TN | TPR | FPR | FP w/ sanitizer noted | F1 |");
    L.push("|---|---:|---:|---:|---:|---:|---:|---:|---:|");
    for (const r of res.rows) {
      const flagged = r.fp ? `${r.fpFlagged}/${r.fp}` : "—";
      L.push(`| ${r.cwe} | ${r.tp} | ${r.fn} | ${r.fp} | ${r.tn} | ${pct(r.tpr)} | ${pct(r.fpr)} | ${flagged} | ${r.f1.toFixed(2)} |`);
    }
    L.push("");
  }
  L.push("## Reading these honestly", "");
  L.push("- A corpus is not a codebase. Synthetic cases are small, single-file and unambiguous;");
  L.push("  they reward a pattern matcher and understate what cross-file analysis is for.");
  L.push("- A **0.00 Youden** row means the class was not enumerated at all on this stack — a");
  L.push("  coverage gap, and more useful to know than a good average.");
  L.push("- Every number here is the MECHANICAL half only: no scanners, no adjudication. The");
  L.push("  audit ultrasec actually produces has a human judging each candidate, which no");
  L.push("  benchmark of this shape can measure.");
  L.push("");
  return L.join("\n");
}

// ── Main ────────────────────────────────────────────────────────────────────
const want = flag("corpus", "all");
const keys = want === "all" ? Object.keys(CORPORA) : [want];
const limit = Number(flag("limit", 0)) || 0;
mkdirSync(cacheRoot, { recursive: true });

const results = {};
for (const key of keys) {
  if (!CORPORA[key]) {
    console.error(`unknown --corpus '${key}' (expected ${Object.keys(CORPORA).join("|")}|all)`);
    process.exit(2);
  }
  const dir = fetchCorpus(key);
  if (!dir) continue;
  const res = scoreCorpus(key, dir, limit);
  if (res) results[key] = res;
}

if (!Object.keys(results).length) {
  console.error("nothing scored — no corpus was available. Nothing written.");
  process.exit(1);
}

const version = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version;
const firstRun = join(cacheRoot, `${Object.keys(results)[0]}.run`, "manifest.json");
const tier = existsSync(firstRun) ? (JSON.parse(readFileSync(firstRun, "utf8")).extraction?.ast ? "AST (tree-sitter)" : "regex fallback") : "unknown";
const md = render(results, { version, tier, date: new Date().toISOString().slice(0, 10) });

if (has("write")) {
  const p = join(root, "docs", "BENCHMARK.md");
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, md);
  console.error(`\nwrote ${p}`);
} else {
  process.stdout.write(md);
  console.error("\n(--write to update docs/BENCHMARK.md)");
}
