import { afterEach, describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runCouncilWith, type CouncilDeps } from "../src/commands/council.js";
import { applyCouncil, parseDecisions } from "../src/council/apply.js";
import { argvMessage, buildDevilList, LANGS, renderBrief } from "../src/council/brief.js";
import { indexTree, parseReport, type Claim } from "../src/council/claims.js";
import { consolidate, cweFamily } from "../src/council/consolidate.js";
import { classifyFailure, detectorFor, digest, isContractShaped } from "../src/council/events.js";
import { loadLedger } from "../src/council/ledger.js";
import { placeholderArtefacts, redactJsonLine, redactReviewerText } from "../src/council/redact.js";
import type { CouncilSpawner } from "../src/council/runner.js";
import { buildArgs, parseCouncilConfig, parseModelList, presetRegistry, PRESETS, reviewersFrom } from "../src/council/reviewers.js";
import { councilEnv, createSnapshot, snapshotFiles } from "../src/council/snapshot.js";
import { countBySeverity, loadDossier, writeDossier } from "../src/store.js";
import type { Finding } from "../src/types.js";
import { captureOutput, parseArgs } from "../src/util.js";

// Every test here runs against SYNTHETIC fixtures and a fake CLI (a node
// script standing in for the preset reviewer CLIs, and for config-defined
// ones, through the command override). No real reviewer CLI and no network is
// ever touched.

const dirs: string[] = [];
const tmp = (p: string): string => {
  const d = mkdtempSync(join(tmpdir(), `ultrasec-council-${p}-`));
  dirs.push(d);
  return d;
};
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

const APP = [
  `import { db } from "./db";`,
  `import express from "express";`,
  `const app = express();`,
  ``,
  `// invoices`,
  `app.get("/invoice/:id", async (req, res) => {`,
  `  const user = req.session.user;`,
  `  if (!user) return res.status(401).end();`,
  `  // no ownership check below`,
  `  const invoice = await db.invoices.find(req.params.id);`,
  `  res.json(invoice);`,
  `});`,
  ``,
  `app.get("/search", async (req, res) => {`,
  `  const q = req.query.q;`,
  `  const rows = await db.raw("SELECT * FROM t WHERE name = '" + q + "'");`,
  `  res.json(rows);`,
  `});`,
  ``,
  `app.get("/go", (req, res) => res.redirect(String(req.query.to)));`,
  ``,
  `export default app;`,
].join("\n");

/** A git repo with tracked code and UNTRACKED secrets beside it. */
function fixtureRepo(): string {
  const repo = tmp("repo");
  const w = (rel: string, body: string) => {
    mkdirSync(join(repo, rel, ".."), { recursive: true });
    writeFileSync(join(repo, rel), body);
  };
  w("src/app.ts", `${APP}\n`);
  w(
    "src/config.ts",
    `// config\nexport const JWT_SECRET = process.env.JWT_SECRET;\nexport const DB_PASSWORD = process.env.DB_PASSWORD;\nexport const port = 3000;\n`,
  );
  w("src/db.ts", `// data layer\nimport { Pool } from "pg";\nexport const pool = new Pool({ password: process.env.DB_PASSWORD });\nexport const db = pool;\n`);
  w("src/util/index.ts", `export const a = 1;\n`);
  w("lib/index.ts", `export const b = 2;\n`);
  const git = (...a: string[]) => execFileSync("git", ["-C", repo, ...a], { stdio: "ignore" });
  git("init", "-q");
  git("add", ".");
  git("-c", "user.email=t@example.com", "-c", "user.name=t", "-c", "commit.gpgsign=false", "commit", "-qm", "init");
  // Never committed: a reviewer must never see these.
  w(".env", "GITHUB_TOKEN=ghp_untrackedSecretValue1234567890abcdef\n");
  w("notes.txt", "scratch\n");
  return repo;
}

/** The run's dossier: one confirmed SQLi at src/app.ts:16, one argued dismissal. */
function fixtureRun(repo: string): string {
  const run = tmp("run");
  const findings: Finding[] = [
    {
      id: "aaaaaaaaaaa1",
      category: "taint",
      cwe: "CWE-89",
      title: "SQL injection: req.query.q reaches db.raw()",
      severity: "high",
      confidence: "high",
      message: "MESSAGE_SHOULD_NOT_LEAK — evidence line with DB_PASSWORD=hunter2",
      tool: "ultrasec",
      status: "confirmed",
      verdict: "supported",
      source: { file: "src/app.ts", line: 15 },
      sink: { file: "src/app.ts", line: 16 },
    },
    {
      id: "bbbbbbbbbbb2",
      category: "sast",
      cwe: "CWE-79",
      title: "Reflected XSS in /search",
      severity: "medium",
      confidence: "low",
      message: "candidate\n\nVerdict (refuted): JSON response, no HTML context",
      tool: "semgrep",
      status: "dismissed",
      verdict: "refuted",
      brocard: "no-threat-model",
      sink: { file: "src/app.ts", line: 17 },
    },
  ];
  writeDossier(run, {
    manifest: {
      version: "test",
      schemaVersion: 11,
      repo,
      generatedNote: "council fixture",
      languages: ["typescript"],
      toolsRun: [],
      counts: { findings: findings.length, bySeverity: countBySeverity(findings) },
    },
    findings,
    graph: { files: [], edges: [], symbolDefs: {} },
  });
  return run;
}

// ── Synthetic reviewer reports ───────────────────────────────────────────────

const REPORT_A = [
  "## Findings",
  "",
  "### R1 — IDOR: any user reads any invoice",
  "- Severity: High",
  "- CWE: CWE-639",
  "- Location: `src/app.ts:10`",
  "- Scenario: any logged-in user · GET /invoice/2 · another user's invoice",
  "- Evidence: > const invoice = await db.invoices.find(req.params.id);",
  "- Fix: compare invoice.ownerId to the session user",
  "",
  "### R2 — Database password committed",
  "- Severity: medium",
  "- CWE: CWE-798",
  "- Location: db.ts:3",
  "- Evidence: `DB_PASSWORD=hunter2hunter2xyz` and the seed hash $argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaA",
  "",
  "### R3 — Something at an invented line",
  "- Severity: low",
  "- Location: `src/app.ts:999`, the DB at `0.0.0.0:5432`, and `index.ts:1`",
  "",
  "### R4 — Production JWT secret replaced",
  "- Severity: critical",
  "- CWE: CWE-798",
  "- Location: `src/config.ts:2`",
  "- Evidence: JWT_SECRET is set to MASKTOOL_9f3a2b1c in production config",
  "",
  "### R5 — SQL injection in search",
  "- Severity: high",
  "- CWE: CWE-89",
  "- Location: `src/app.ts:16`",
  "",
  "## To verify",
  "- example-lib 2.1.2 is the fixed version",
  "",
  "## Coverage",
  "- src/ reviewed",
].join("\n");

const REPORT_B = [
  "### K1 — Missing ownership check on invoice read",
  "- Sévérité : haute",
  "- CWE : CWE-862",
  "- Emplacement : `src/app.ts:11`",
  "",
  "## Couverture",
  "- tout src/",
].join("\n");

const REPORT_DEVIL = [
  "## A. Contestations",
  "",
  "### aaaaaaaaaaa1 — the query is not reachable unauthenticated",
  "- Proof: `src/app.ts:8` returns 401 first",
  "",
  "## B. Nouveaux findings",
  "",
  "### D1 — Open redirect on /go",
  "- Sévérité : moyenne",
  "- CWE-601",
  "- Emplacement : `src/app.ts:20`",
  "",
  "## C. Couverture",
  "- routes",
].join("\n");

/**
 * The fake CLI: one node script standing in for the `jsonl-steps` presets, a
 * `text` preset, and a config-defined reviewer that writes its report to a file
 * (`review … --out <file>`). Its behaviour is keyed on the model name, and every
 * call is logged — argv, env, cwd — to a file OUTSIDE the snapshot.
 */
function fakeCli(): { script: string; log: string; calls: () => { args: string[]; env: Record<string, string>; cwd: string; brief: string | null }[] } {
  const dir = tmp("fake");
  const log = join(dir, "calls.jsonl");
  const script = join(dir, "fake-cli.mjs");
  const reports = { a: REPORT_A, b: REPORT_B, devil: REPORT_DEVIL };
  writeFileSync(
    script,
    `
import { appendFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
const REPORTS = ${JSON.stringify(reports)};
const args = process.argv.slice(2);
const val = (f) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : undefined; };
const text = args.includes("-p");
const fileMode = args[0] === "review";
const pointed = fileMode ? val("--brief") : (text ? val("-p") : args[args.length - 1]).match(/_COUNCIL_BRIEF[\\w.-]+\\.md/)?.[0];
const brief = pointed && existsSync(pointed) ? readFileSync(pointed, "utf8") : null;
appendFileSync(${JSON.stringify(log)}, JSON.stringify({ args, env: process.env, cwd: process.cwd(), brief }) + "\\n");
if (fileMode) { writeFileSync(val("--out"), REPORTS.a); process.stdout.write("done\\n"); process.exit(0); }
const model = val("-m") ?? val("--model") ?? process.env.VIBE_ACTIVE_MODEL ?? "";
const session = val("-s");
const msg = text ? val("-p") : args[args.length - 1];
const key = model.split("/").pop();
const sid = session ?? "ses_" + key.replace(/\\W/g, "");
const ev = (o) => process.stdout.write(JSON.stringify({ sessionID: sid, ...o }) + "\\n");
const step = (cost) => ev({ type: "step_finish", part: { type: "step-finish", tokens: { input: 1000, output: 200, reasoning: 50, cache: { read: 300, write: 10 } }, cost } });
const say = (t, m) => ev({ type: "text", part: { type: "text", messageID: m, text: t } });
if (text) { process.stdout.write(REPORTS[key] ?? ""); process.exit(0); }
const finalizing = !!session && /_COUNCIL_BRIEF/.test(msg);
ev({ type: "step_start", part: { type: "step-start" } });
if (model.includes("504")) {
  ev({ type: "error", error: { name: "APIError", data: { message: "Upstream idle timeout", statusCode: 504 } } });
  process.exit(1);
}
if (finalizing) { say(REPORTS[model.includes("notes") || model.includes("pricey") ? "b" : "a"], "m9"); step(0.001); process.exit(0); }
if (model.includes("quota")) {
  say("Reading the invoice router first.", "m1");
  step(0.005);
  ev({ type: "error", error: { name: "APIError", data: { message: "Rate limit exceeded. Your limit will reset at 2026-10-09 01:52:02", statusCode: 429 } } });
  process.exit(1);
}
if (model.includes("credit")) {
  ev({ type: "error", error: { code: "insufficient_quota", message: "You have run out of credits" } });
  process.exit(1);
}
if (model.includes("notes")) { say("I will start by mapping the routes, then the data layer.", "m1"); step(0.002); process.exit(0); }
if (model.includes("pricey")) { say("exploring", "m1"); step(1.5); step(1.5); setTimeout(() => process.exit(0), 20000); }
else {
  say("Let me read the router.", "m1");
  ev({ type: "tool_use", part: { type: "tool", tool: "read", state: { output: "JWT_SECRET=supersecretvalue123" } } });
  step(0.01);
  say(REPORTS[key] ?? "", "m2");
  step(0.02);
}
`,
  );
  const calls = () =>
    existsSync(log)
      ? readFileSync(log, "utf8")
          .trim()
          .split("\n")
          .map((l) => JSON.parse(l))
      : [];
  return { script, log, calls };
}

function deps(script: string, spawnCount?: { n: number }, configHome?: string): CouncilDeps {
  const prefix = [process.execPath, script];
  return {
    commands: { opencode: prefix, kilo: prefix, vibe: prefix, claude: prefix, codex: prefix, mycli: prefix, "oc-strict": prefix },
    // Hermetic: the default config location is a temp dir, never the developer's own.
    baseEnv: { ...process.env, XDG_CONFIG_HOME: configHome ?? tmp("xdg") },
    ...(spawnCount
      ? {
          spawner: (async () => {
            spawnCount.n++;
            throw new Error("must not spawn");
          }) as CouncilSpawner,
        }
      : {}),
  };
}

const council = async (argv: string[], d: CouncilDeps) => captureOutput(() => runCouncilWith(parseArgs(["council", ...argv]), d));

// ── Snapshot & environment ───────────────────────────────────────────────────

describe("council snapshot", () => {
  it("is HEAD's tracked tree only: no untracked .env, same line numbers", () => {
    const repo = fixtureRepo();
    const snap = createSnapshot(repo, join(tmp("snap"), "snapshot"));
    const files = snapshotFiles(snap.dir);
    expect(files).toContain("src/app.ts");
    expect(files).not.toContain(".env");
    expect(files).not.toContain("notes.txt");
    expect(readFileSync(join(snap.dir, "src/app.ts"), "utf8")).toBe(readFileSync(join(repo, "src/app.ts"), "utf8"));
  });

  it("refuses a directory that is not a git checkout", () => {
    expect(() => createSnapshot(tmp("nogit"), join(tmp("snap"), "s"))).toThrow(/not a git checkout/);
  });

  it("starts every CLI with HOME, PATH and TERM=dumb — nothing else", () => {
    const env = councilEnv({ VIBE_ACTIVE_MODEL: "m" }, { HOME: "/h", PATH: "/p", GITHUB_TOKEN: "ghp_x", AWS_SECRET_ACCESS_KEY: "y" });
    expect(env).toEqual({ HOME: "/h", PATH: "/p", TERM: "dumb", VIBE_ACTIVE_MODEL: "m" });
  });
});

// ── Plan mode: zero calls ────────────────────────────────────────────────────

describe("council without --models", () => {
  it("prints the plan and makes ZERO spawns", async () => {
    const repo = fixtureRepo();
    const run = fixtureRun(repo);
    const count = { n: 0 };
    const out = await council(["--run", run, "--repo", repo], deps("/nonexistent", count));
    expect(out.result).toBe(0);
    expect(count.n).toBe(0);
    expect(out.stdout).toMatch(/ZERO external calls/);
    expect(existsSync(join(run, "council", "snapshot"))).toBe(false); // nothing written either
  });
});

// ── Blind pass end to end, through the fake CLI ──────────────────────────────

describe("council --models (blind)", () => {
  it("runs reviewers in parallel on the snapshot, with an emptied env and a short argv", async () => {
    const repo = fixtureRepo();
    const run = fixtureRun(repo);
    const fake = fakeCli();
    process.env.COUNCIL_PARENT_TOKEN = "parent-shell-token-must-not-leak";
    let out: Awaited<ReturnType<typeof council>>;
    try {
      out = await council(["--run", run, "--repo", repo, "--models", "opencode:prov/a,kilo:prov/b"], deps(fake.script));
    } finally {
      delete process.env.COUNCIL_PARENT_TOKEN;
    }
    expect(out.result).toBe(0);
    const calls = fake.calls();
    expect(calls).toHaveLength(2);
    const snapshot = join(run, "council", "snapshot");
    for (const c of calls) {
      // macOS resolves the tmp dir through /private; compare real paths.
      // Emptied environment: exactly HOME, PATH, TERM (node adds nothing of the parent's).
      expect(c.env.COUNCIL_PARENT_TOKEN).toBeUndefined();
      expect(c.env.TERM).toBe("dumb");
      expect(Object.keys(c.env).filter((k) => !["HOME", "PATH", "TERM", "__CF_USER_TEXT_ENCODING"].includes(k))).toEqual([]);
      // Runs IN the snapshot, told to read a brief file — never handed the brief itself.
      expect(c.cwd).toBe(join(realpathSync(run), "council", "snapshot"));
      const msg = c.args.at(-1)!;
      expect(msg.length).toBeLessThan(300);
      expect(msg).toMatch(/_COUNCIL_BRIEF\.blind\.(opencode|kilo)\.md/);
    }
    // The read-only agent, with user plugins off.
    const oc = calls.find((c) => c.args.includes("prov/a"))!;
    expect(oc.args).toEqual(expect.arrayContaining(["--agent", "plan", "--pure", "--format", "json", "--dir", snapshot]));
    const kc = calls.find((c) => c.args.includes("kilo/prov/b"))!;
    expect(kc.args).toEqual(expect.arrayContaining(["--auto", "--agent", "plan"]));
    // The brief was a file inside the snapshot when the reviewer ran, carrying the
    // output contract; a copy stays beside the logs.
    expect(oc.brief).toMatch(/### <ID> — <title>/);
    expect(oc.brief).toMatch(/no git history/);
    expect(readFileSync(join(run, "council", "blind", "opencode", "brief.md"), "utf8")).toBe(oc.brief);
    // The source copy does not outlive the command (a later scan would index it).
    expect(existsSync(snapshot)).toBe(false);

    // Usage aggregated from step_finish events, recorded in the ledger.
    const ledger = loadLedger(run)!;
    const a = ledger.reviewers.find((r) => r.name === "opencode")!;
    expect(a.status).toBe("ok");
    expect(a.session).toBe("ses_a");
    expect(a.usage).toMatchObject({ exposed: true, input: 2000, output: 400, reasoning: 100, cacheRead: 600, steps: 2, cost: 0.03 });
    expect(ledger.totals.cost).toBeCloseTo(0.06);

    // Logs, redacted: out.md is the LAST message's text (the report), events stay valid JSONL.
    const outMd = readFileSync(join(run, "council", "blind", "opencode", "out.md"), "utf8");
    expect(outMd).toMatch(/^## Findings/);
    expect(outMd).not.toContain("hunter2hunter2xyz");
    expect(outMd).not.toContain("c2FsdHNhbHRzYWx0");
    const events = readFileSync(join(run, "council", "blind", "opencode", "events.jsonl"), "utf8")
      .trim()
      .split("\n");
    for (const l of events) expect(() => JSON.parse(l)).not.toThrow();
    expect(events.join("\n")).not.toContain("supersecretvalue123");

    // The worklist: IDOR raised by both → one candidate, corroboration 2.
    const todo = JSON.parse(readFileSync(join(run, "council", "COUNCIL.todo.json"), "utf8"));
    // Titled after the first reviewer in name order; both claims are listed.
    const idor = todo.candidates.find((c: { title: string }) => /ownership check/.test(c.title));
    expect(idor.claims.map((c: { ref: string }) => c.ref)).toEqual(["K1", "R1"]);
    expect(idor.sources).toEqual(["kilo", "opencode"]);
    expect(idor.corroboration).toBe(2);
    // The SQLi lands on the finding the run already holds: reported by id, not as a candidate.
    expect(todo.corroborations.map((c: { findingId: string }) => c.findingId)).toEqual(["aaaaaaaaaaa1"]);
    expect(todo.candidates.some((c: { title: string }) => /SQL injection/.test(c.title))).toBe(false);
    expect(readFileSync(join(run, "council", "COUNCIL.md"), "utf8")).toMatch(/Corroborations of findings the run already holds/);
    // Nothing written outside <run>/council/ (findings untouched).
    expect(loadDossier(run).findings).toHaveLength(2);
  });

  it("vibe: model through the environment, text output, usage not exposed", async () => {
    const repo = fixtureRepo();
    const run = fixtureRun(repo);
    const fake = fakeCli();
    const out = await council(["--run", run, "--repo", repo, "--models", "vibe:b"], deps(fake.script));
    expect(out.result).toBe(0);
    const [call] = fake.calls();
    expect(call!.env.VIBE_ACTIVE_MODEL).toBe("b");
    expect(call!.args).toEqual(expect.arrayContaining(["--agent", "plan", "--trust", "--output", "text"]));
    const rec = loadLedger(run)!.reviewers[0]!;
    expect(rec.status).toBe("ok");
    expect(rec.usage.exposed).toBe(false);
  });
});

// ── Interruption: quota, fallback chain, budget, resume ──────────────────────

describe("council interruption handling", () => {
  it("quota → resumes the SAME session for one turn on the fallback chain, past a transient 504", async () => {
    const repo = fixtureRepo();
    const run = fixtureRun(repo);
    const fake = fakeCli();
    const out = await council(
      ["--run", run, "--repo", repo, "--models", "kilo:prov/quota", "--fallback", "kilo:prov/flaky-504,kilo:prov/backup-ok"],
      deps(fake.script),
    );
    expect(out.result).toBe(0);
    const calls = fake.calls();
    expect(calls).toHaveLength(3);
    expect(calls[0]!.args).not.toContain("-s");
    for (const c of calls.slice(1)) {
      expect(c.args).toEqual(expect.arrayContaining(["-s", "ses_quota"]));
      expect(c.args.at(-1)).toMatch(/Stop exploring now and do not call any tool/);
    }
    // The preset's modelPrefix is applied to fallbacks too.
    expect(calls[1]!.args).toContain("kilo/prov/flaky-504");
    expect(calls[2]!.args).toContain("kilo/prov/backup-ok");
    const rec = loadLedger(run)!.reviewers[0]!;
    expect(rec.attempts.map((a) => a.status)).toEqual(["quota", "transient", "ok"]);
    expect(rec.status).toBe("ok");
  });

  it("quota with no fallback → recorded with the reset time; `--resume` finalises it later", async () => {
    const repo = fixtureRepo();
    const run = fixtureRun(repo);
    const fake = fakeCli();
    const first = await council(["--run", run, "--repo", repo, "--models", "opencode:prov/quota"], deps(fake.script));
    expect(first.result).toBe(1);
    let rec = loadLedger(run)!.reviewers[0]!;
    expect(rec.status).toBe("quota");
    expect(rec.resetAt).toBe("2026-10-09 01:52:02");
    expect(first.stdout).toMatch(/quota resets at 2026-10-09 01:52:02/);

    const again = await council(["--run", run, "--resume", "opencode"], deps(fake.script));
    expect(again.result).toBe(0);
    expect(again.stdout).toMatch(/resets at 2026-10-09 01:52:02/);
    const last = fake.calls().at(-1)!;
    expect(last.args).toEqual(expect.arrayContaining(["-s", "ses_quota", "-m", "prov/quota"]));
    rec = loadLedger(run)!.reviewers[0]!;
    expect(rec.status).toBe("ok");
    expect(rec.attempts.map((a) => a.status)).toEqual(["quota", "ok"]);
    expect(existsSync(join(run, "council", "blind", "opencode", "out.md"))).toBe(true);
  });

  it("credit exhaustion is told apart from a quota", async () => {
    const repo = fixtureRepo();
    const run = fixtureRun(repo);
    const fake = fakeCli();
    await council(["--run", run, "--repo", repo, "--models", "kilo:prov/credit"], deps(fake.script));
    expect(loadLedger(run)!.reviewers[0]!.status).toBe("credit");
  });

  it("progress notes only (no report) → one closing turn on the same model", async () => {
    const repo = fixtureRepo();
    const run = fixtureRun(repo);
    const fake = fakeCli();
    const out = await council(["--run", run, "--repo", repo, "--models", "opencode:prov/notes"], deps(fake.script));
    expect(out.result).toBe(0);
    const rec = loadLedger(run)!.reviewers[0]!;
    expect(rec.attempts.map((a) => [a.status, a.resume, a.model])).toEqual([
      ["no-report", false, "prov/notes"],
      ["ok", true, "prov/notes"],
    ]);
  });

  it("--max-cost stops a reviewer from its own events, then finalises it", async () => {
    const repo = fixtureRepo();
    const run = fixtureRun(repo);
    const fake = fakeCli();
    const t0 = Date.now();
    const out = await council(["--run", run, "--repo", repo, "--models", "opencode:prov/pricey", "--max-cost", "2"], deps(fake.script));
    expect(Date.now() - t0).toBeLessThan(15000); // killed, not waited out
    expect(out.result).toBe(0);
    expect(loadLedger(run)!.reviewers[0]!.attempts.map((a) => a.status)).toEqual(["budget", "ok"]);
  });

  it("an unknown reviewer in --models fails closed, naming the known ones", async () => {
    const repo = fixtureRepo();
    const run = fixtureRun(repo);
    const count = { n: 0 };
    const out = await council(["--run", run, "--repo", repo, "--models", "nosuch:prov/m"], deps("/x", count));
    expect(out.result).toBe(2);
    expect(count.n).toBe(0);
    expect(out.stderr).toMatch(/unknown reviewer "nosuch"/);
    expect(out.stderr).toMatch(/known: opencode, kilo, vibe, claude, codex/);
    expect(out.stderr).toMatch(/--reviewer-config/);
  });
});

// ── Event parsing ────────────────────────────────────────────────────────────

describe("reviewer event parsing", () => {
  it("aggregates tokens/cost per step and keeps the LAST message as the report", () => {
    const lines = [
      { type: "step_start", sessionID: "ses_1", part: {} },
      { type: "text", sessionID: "ses_1", part: { messageID: "m1", text: "let me look around" } },
      { type: "step_finish", sessionID: "ses_1", part: { tokens: { input: 10, output: 5, reasoning: 1, cache: { read: 2, write: 3 } }, cost: 0.1 } },
      { type: "text", sessionID: "ses_1", part: { messageID: "m2", text: "### R1 — x" } },
      { type: "step_finish", sessionID: "ses_1", part: { tokens: { input: 10, output: 5, reasoning: 1, cache: { read: 2, write: 3 } }, cost: 0.2 } },
    ];
    const d = digest(PRESETS.opencode!, lines.map((l) => JSON.stringify(l)).join("\n"), "", 0);
    expect(d.session).toBe("ses_1");
    expect(d.text).toBe("### R1 — x");
    expect(d.usage).toMatchObject({ input: 20, output: 10, reasoning: 2, cacheRead: 4, cacheWrite: 6, steps: 2 });
    expect(d.usage.cost).toBeCloseTo(0.3);
  });

  it("classifies stops with generic phrasings, whatever the provider", () => {
    const quota = [
      "Usage limit hit: your limit will reset at 2026-10-09 01:52:02",
      "Rate limit exceeded, please retry later",
      '{"error":{"type":"rate_limit_error","message":"slow down"}}',
      "Quota exceeded for this project",
      "429 Too Many Requests",
    ];
    for (const m of quota) expect(classifyFailure(m).kind, m).toBe("quota");
    const credit = [
      '{"error":{"code":"insufficient_quota"}}',
      "Insufficient balance on your account",
      "You have run out of credits",
      "Low credit: top up to continue",
      "HTTP 402 Payment Required",
    ];
    for (const m of credit) expect(classifyFailure(m).kind, m).toBe("credit");
    const transient = [
      "504 Gateway Timeout",
      "upstream idle timeout",
      "503 Service Unavailable",
      "read ECONNRESET",
      "the model is overloaded",
      "request timed out",
    ];
    for (const m of transient) expect(classifyFailure(m).kind, m).toBe("transient");
    expect(classifyFailure("TypeError: boom").kind).toBe("error");
  });

  it("extracts an announced reset as a generic date-time, and only on a quota or credit stop", () => {
    expect(classifyFailure("Your limit will reset at 2026-10-09 01:52:02").resetAt).toBe("2026-10-09 01:52:02");
    expect(classifyFailure("rate limit hit; resets 2026-10-09T01:52:02Z").resetAt).toBe("2026-10-09T01:52:02Z");
    expect(classifyFailure("503 at 2026-10-09 01:52:02").resetAt).toBeUndefined();
  });

  it("counts a bare HTTP status only in a structured error, never in prose", () => {
    expect(classifyFailure('{"statusCode":429}').kind).toBe("quota");
    expect(classifyFailure('{"statusCode":429}', detectorFor(undefined), false).kind).toBe("error");
    // A text CLI's stderr echoing a report line is not a stop.
    const text = PRESETS.codex!;
    expect(digest(text, "", "see src/app.ts:429 for the rate limiting logic", 0).failure).toBeUndefined();
    expect(digest(text, "", "ERROR: quota exceeded for this account", 0).failure?.kind).toBe("quota");
  });

  it("a reviewer's own patterns win over the generic ones", () => {
    const d = detectorFor({ creditPatterns: ["plan allowance spent"], transientPatterns: ["^E_RETRY\\b"] });
    expect(classifyFailure("plan allowance spent for this cycle", d).kind).toBe("credit");
    expect(classifyFailure("E_RETRY backend busy", d).kind).toBe("transient");
    expect(classifyFailure("plan allowance spent for this cycle").kind).toBe("error");
  });

  it("a report is contract-shaped in any locale; progress notes are not", () => {
    expect(isContractShaped("### R1 — t")).toBe(true);
    expect(isContractShaped("## Coverage\n- nothing")).toBe(true);
    expect(isContractShaped("## C. Coverage\n- nothing")).toBe(true);
    expect(isContractShaped("## Couverture\n- rien")).toBe(true);
    expect(isContractShaped("I will now read the router.")).toBe(false);
  });
});

// ── Claims ───────────────────────────────────────────────────────────────────

function snapIndex() {
  const repo = fixtureRepo();
  const snap = createSnapshot(repo, join(tmp("snap"), "snapshot"));
  return indexTree(snap.dir, snapshotFiles(snap.dir));
}

describe("claim parsing", () => {
  it("extracts title/severity/CWE and resolves every citation against the snapshot", () => {
    const idx = snapIndex();
    const claims = parseReport(REPORT_A, { reviewer: "opencode", phase: "blind" }, idx);
    expect(claims.map((c) => c.ref)).toEqual(["R1", "R2", "R3", "R4", "R5"]); // To verify / Coverage carry no claims
    const [r1, r2, r3, r4] = claims as [Claim, Claim, Claim, Claim];
    expect(r1).toMatchObject({ title: "IDOR: any user reads any invoice", severity: "high", cwe: "CWE-639" });
    expect(r1.citations).toEqual([expect.objectContaining({ file: "src/app.ts", line: 10, citation: "ok" })]);
    // A bare basename resolves only because exactly one file carries it.
    expect(r2.citations[0]).toMatchObject({ file: "src/db.ts", line: 3, citation: "ok", resolvedFrom: "db.ts" });
    // Out of range → unresolved; host:port → not a citation; an ambiguous basename → unresolved.
    expect(r3.citations.map((c) => [c.raw, c.citation])).toEqual([
      ["src/app.ts:999", "unresolved"],
      ["index.ts:1", "unresolved"],
    ]);
    expect(r3.citations[1]!.reason).toMatch(/ambiguous basename \(2 files\)/);
    // A masking placeholder is flagged as an artefact, never taken as a fact.
    expect(r4.artefacts).toEqual(["MASKTOOL_9f3a2b1…"]);
    // Secrets never survive into a claim.
    expect(r2.excerpt).not.toContain("hunter2hunter2xyz");
    expect(r2.excerpt).toContain("DB_PASSWORD=hunt…");
  });

  it("parses a French devil's-advocate report into contestations and new findings", () => {
    const idx = snapIndex();
    const claims = parseReport(REPORT_DEVIL, { reviewer: "vibe", phase: "devil" }, idx);
    expect(claims.map((c) => [c.section, c.ref])).toEqual([
      ["contest", "aaaaaaaaaaa1"],
      ["new", "D1"],
    ]);
    expect(claims[1]).toMatchObject({ severity: "medium", cwe: "CWE-601" });
  });

  it("marks advisory and history claims as needing engine verification", () => {
    const idx = snapIndex();
    const [c] = parseReport(
      "### R1 — vulnerable example-lib\n- Severity: high\n- `src/app.ts:1` example-lib 2.1.2 is the fixed version (CVE-2099-12345)",
      { reviewer: "x", phase: "blind" },
      idx,
    );
    expect(c!.verify.join(" ")).toMatch(/dependency-scanner/);
    expect(c!.cves).toEqual(["CVE-2099-12345"]);
  });
});

// ── Redaction ────────────────────────────────────────────────────────────────

describe("redaction", () => {
  it("masks a modular-crypt hash, NAME=secret, quoted secrets, JWTs and long tokens", () => {
    const s = redactReviewerText(
      [
        "hash $argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo",
        "GRAPHQL_ADMIN_SECRET=adminsecret123",
        `"jwt_secret": "my-very-secret"`,
        "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.c2lnbmF0dXJlLXZhbHVl",
        "key a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
      ].join("\n"),
    );
    expect(s).toContain("$argon2id$v=19$m=65536,t=3,p=4$…");
    expect(s).not.toContain("aGFzaGhhc2hoYXNo");
    expect(s).toContain("GRAPHQL_ADMIN_SECRET=admi…");
    expect(s).not.toContain("my-very-secret");
    expect(s).not.toContain("eyJzdWIiOiIxMjM0NTYifQ");
    expect(s).not.toContain("a1b2c3d4e5f6a7b8c9d0");
  });

  it("leaves references and ordinary code readable", () => {
    const code = "const s = process.env.JWT_SECRET;\nDB_PASSWORD=$DB_PASSWORD\npassword: req.body.password\nsrc/components/Button/index.tsx";
    expect(redactReviewerText(code)).toBe(code);
  });

  it("keeps a JSONL event valid when a secret follows an escaped newline", () => {
    const line = JSON.stringify({ part: { text: "a\nTOKEN=abcdef123456 and a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0" } });
    const out = redactJsonLine(line);
    expect(() => JSON.parse(out)).not.toThrow();
    expect(out).not.toContain("abcdef123456");
  });

  it("our own marker is not mistaken for a masking placeholder on re-parse", () => {
    expect(placeholderArtefacts(redactReviewerText("PASSWORD=hunter2"))).toEqual([]);
    expect(placeholderArtefacts("set to REDACTED")).toEqual(["REDACTED"]);
    expect(placeholderArtefacts("**bold** and ***strong***")).toEqual([]);
  });
});

// ── Consolidation ────────────────────────────────────────────────────────────

describe("dedupe & corroboration", () => {
  const claim = (reviewer: string, ref: string, cwe: string | undefined, file: string, line: number): Claim => ({
    reviewer,
    phase: "blind",
    section: "finding",
    ref,
    title: `${ref} title`,
    severity: "high",
    ...(cwe ? { cwe } : {}),
    citations: [{ raw: `${file}:${line}`, file, line, citation: "ok" }],
    excerpt: "",
    artefacts: [],
    verify: [],
    cves: [],
  });

  it("groups by file + ±3 lines + CWE family; corroboration is the count of reviewers", () => {
    const todo = consolidate(
      [
        claim("a", "R1", "CWE-639", "src/x.ts", 10),
        claim("b", "K1", "CWE-862", "src/x.ts", 13),
        claim("c", "V1", "CWE-89", "src/x.ts", 11),
        claim("d", "Z1", "CWE-639", "src/x.ts", 30),
      ],
      [],
      "c0ffee",
    );
    const ac = todo.candidates.filter((c) => c.family === "access-control");
    expect(ac.map((c) => c.sources)).toEqual([["a", "b"], ["d"]]);
    expect(todo.candidates.find((c) => c.family === "injection")!.sources).toEqual(["c"]);
  });

  it("is deterministic — same claims, same ids", () => {
    const cs = [claim("b", "K1", "CWE-862", "src/x.ts", 13), claim("a", "R1", "CWE-639", "src/x.ts", 10)];
    expect(consolidate(cs, [], "c").candidates).toEqual(consolidate([...cs].reverse(), [], "c").candidates);
    expect(cweFamily("CWE-943")).toBe(cweFamily("CWE-89"));
  });
});

// ── Devil's advocate input ───────────────────────────────────────────────────

describe("devil's-advocate list", () => {
  it("carries id/severity/status/title/citations and the rejected reasons — never messages", () => {
    const repo = fixtureRepo();
    const run = fixtureRun(repo);
    const list = buildDevilList(loadDossier(run).findings, [{ id: "C-1", title: "Old claim", reason: "mitigated by CSP" }]);
    expect(list.items).toEqual([
      {
        id: "aaaaaaaaaaa1",
        severity: "high",
        status: "confirmed",
        title: "SQL injection: req.query.q reaches db.raw()",
        at: ["src/app.ts:15", "src/app.ts:16"],
      },
    ]);
    expect(list.rejected.map((r) => r.id)).toEqual(["bbbbbbbbbbb2", "C-1"]);
    const brief = renderBrief({ lang: "fr", phase: "devil", commit: "abc", devil: list });
    expect(brief).toMatch(/## A\. Contestations/);
    expect(brief).toMatch(/## B\. Nouveaux findings/);
    expect(brief).not.toContain("MESSAGE_SHOULD_NOT_LEAK");
    expect(brief).not.toContain("hunter2");
    expect(argvMessage("fr", "devil", "vibe")).toMatch(/_COUNCIL_BRIEF\.devil\.vibe\.md/);
  });
});

// ── Apply ────────────────────────────────────────────────────────────────────

describe("council --apply", () => {
  async function blindThenDevil() {
    const repo = fixtureRepo();
    const run = fixtureRun(repo);
    const fake = fakeCli();
    await council(["--run", run, "--repo", repo, "--models", "opencode:prov/a,kilo:prov/b"], deps(fake.script));
    await council(["--run", run, "--repo", repo, "--phase", "devil", "--lang", "fr", "--models", "vibe:devil"], deps(fake.script));
    const todo = JSON.parse(readFileSync(join(run, "council", "COUNCIL.todo.json"), "utf8"));
    const find = (re: RegExp) => todo.candidates.find((c: { title: string }) => re.test(c.title)).id as string;
    return { repo, run, todo, find };
  }

  it("accepts through the citation gate, records rejections with reasons, never applies contestations", async () => {
    const { run, todo, find } = await blindThenDevil();
    expect(todo.contested).toEqual([expect.objectContaining({ id: "aaaaaaaaaaa1", known: "finding", reviewer: "vibe" })]);
    const decisions = [
      { id: find(/ownership check/), decision: "accept", reason: "reproduced: no ownership check" },
      { id: find(/JWT secret/), decision: "reject", reason: "the value is our own masking hook's placeholder" },
      { id: find(/invented line/), decision: "accept", reason: "" },
      { id: find(/password committed/), decision: "accept", reason: "", line: 999 },
      { id: find(/Open redirect/), decision: "reject" }, // no reason: dropped
    ];
    const file = join(tmp("dec"), "decisions.json");
    writeFileSync(file, JSON.stringify(decisions));
    const out = await council(["--run", run, "--apply", file], {});
    expect(out.result).toBe(0);

    const findings = loadDossier(run).findings;
    const added = findings.filter((f) => f.tool === "ultrasec-ai");
    expect(added).toHaveLength(1);
    expect(added[0]).toMatchObject({ title: "Missing ownership check on invoice read", status: "open", category: "authz", severity: "high", cwe: "CWE-862" });
    expect(added[0]!.message).toMatch(/raised by kilo, opencode/);
    // The contested finding is untouched.
    expect(findings.find((f) => f.id === "aaaaaaaaaaa1")!.status).toBe("confirmed");

    const ledger = loadLedger(run)!;
    expect(ledger.decisions.accepted.map((d) => d.findingId)).toEqual([added[0]!.id]);
    expect(ledger.decisions.rejected.map((d) => [d.by, d.reason])).toEqual([
      ["orchestrator", "the value is our own masking hook's placeholder"],
      ["citation-gate", expect.stringMatching(/^line out of range: src\/db\.ts:999/)],
    ]);
    expect(out.stdout).toMatch(/no resolvable citation/); // the invented-line candidate is refused
    expect(out.stdout).toMatch(/a reject must say why/);
    expect(out.stdout).toMatch(/contested finding\(s\) stay a worklist/);
  });

  it("--strict exits 1 when anything was refused", async () => {
    const { run, find } = await blindThenDevil();
    const file = join(tmp("dec"), "decisions.json");
    writeFileSync(file, JSON.stringify([{ id: find(/invented line/), decision: "accept", reason: "" }]));
    expect((await council(["--run", run, "--apply", file, "--strict"], {})).result).toBe(1);
  });

  it("parseDecisions is fail-closed on the container and on an all-bad file", () => {
    expect(() => parseDecisions(`{"nope": 1}`)).toThrow(/fail-closed/);
    expect(() => parseDecisions(`[{"id": "C-1", "decision": "maybe"}]`)).toThrow(/none usable/);
  });

  it("applyCouncil refuses a decision naming no candidate", () => {
    const repo = fixtureRepo();
    const run = fixtureRun(repo);
    const res = applyCouncil(
      loadDossier(run),
      { schema: 1, commit: "c", candidates: [], corroborations: [], contested: [] },
      [{ id: "C-nope", decision: "accept", reason: "" }],
      repo,
    );
    expect(res.refused).toEqual([{ id: "C-nope", reason: expect.stringMatching(/no such candidate/) }]);
  });
});

describe("reviewer presets", () => {
  const reg = presetRegistry();
  const values = { model: "m", dir: "/s", message: "x", title: "t", maxTurns: "5", brief: "b.md", briefPath: "/s/b.md", outFile: "/o" };

  it("splits reviewer:model on the first colon only (a model id may carry one)", () => {
    expect(parseModelList("kilo:prov/x:variant,opencode:a/b", "--models", reg)).toEqual([
      { cli: "kilo", model: "prov/x:variant" },
      { cli: "opencode", model: "a/b" },
    ]);
    expect(reviewersFrom(parseModelList("kilo:a,kilo:b", "--models", reg)).map((r) => r.name)).toEqual(["kilo", "kilo-2"]);
  });

  it("keeps each preset's validated argv", () => {
    expect(buildArgs(PRESETS.opencode!, values, false)).toEqual([
      "run",
      "-m",
      "m",
      "--agent",
      "plan",
      "--pure",
      "--dir",
      "/s",
      "--format",
      "json",
      "--title",
      "t",
      "x",
    ]);
    expect(buildArgs(PRESETS.kilo!, { ...values, session: "S" }, true)).toEqual([
      "run",
      "-s",
      "S",
      "-m",
      "kilo/m",
      "--agent",
      "plan",
      "--pure",
      "--auto",
      "--dir",
      "/s",
      "--format",
      "json",
      "--title",
      "t",
      "x",
    ]);
    expect(buildArgs(PRESETS.vibe!, values, false)).toEqual([
      "-p",
      "x",
      "--agent",
      "plan",
      "--trust",
      "--workdir",
      "/s",
      "--max-turns",
      "5",
      "--output",
      "text",
    ]);
  });

  it("drops an argument group whose placeholder has no value", () => {
    expect(buildArgs(PRESETS.claude!, { ...values, model: "" }, false)).not.toContain("--model");
    expect(buildArgs(PRESETS.codex!, { ...values, model: "" }, false)).toEqual(["exec", "--sandbox", "read-only", "--skip-git-repo-check", "-C", "/s", "x"]);
  });

  it("a reviewer with no resumeArgs, or no session, cannot resume", () => {
    expect(buildArgs(PRESETS.codex!, { ...values, session: "s" }, true)).toBeNull();
    expect(buildArgs(PRESETS.vibe!, { ...values, session: "s" }, true)).toBeNull();
    expect(buildArgs(PRESETS.opencode!, values, true)).toBeNull();
  });

  it("presets name no model", () => {
    for (const spec of Object.values(PRESETS)) {
      // No `<provider>/<model>` literal anywhere: the model is always the user's.
      expect(JSON.stringify({ ...spec, readOnly: "", description: "" }), spec.name).not.toMatch(/"[\w.-]+\/[\w.:-]+"/);
    }
  });
});

// ── Reviewers as data: config files ──────────────────────────────────────────

describe("council reviewer config", () => {
  const writeConfig = (doc: unknown, dir = tmp("cfg")): string => {
    const f = join(dir, "council.json");
    writeFileSync(f, JSON.stringify(doc));
    return f;
  };
  /** A reviewer that exists ONLY in a config file: report written to {outFile}. */
  const MYCLI = {
    bin: "mycli-not-installed",
    args: ["review", "--in", "{dir}", ["--model", "{model}"], "--brief", "{briefPath}", "--out", "{outFile}"],
    events: "none",
    readOnly: "test double: reads the brief, writes only {outFile}",
  };

  it("runs a reviewer defined only in --reviewer-config, end to end", async () => {
    const repo = fixtureRepo();
    const run = fixtureRun(repo);
    const fake = fakeCli();
    const cfg = writeConfig({ reviewers: { mycli: MYCLI } });
    const out = await council(["--run", run, "--repo", repo, "--reviewer-config", cfg, "--models", "mycli:prov/x"], deps(fake.script));
    expect(out.result).toBe(0);
    const [call] = fake.calls();
    expect(call!.args.slice(0, 3)).toEqual(["review", "--in", join(run, "council", "snapshot")]);
    expect(call!.args).toEqual(expect.arrayContaining(["--model", "prov/x"]));
    expect(call!.brief).toMatch(/### <ID> — <title>/);
    const rec = loadLedger(run)!.reviewers[0]!;
    expect(rec).toMatchObject({ name: "mycli", cli: "mycli", status: "ok" });
    expect(rec.usage.exposed).toBe(false);
    // The file report became the redacted out.md, and the raw file is gone.
    const dir = join(run, "council", "blind", "mycli");
    expect(readFileSync(join(dir, "out.md"), "utf8")).toMatch(/^## Findings/);
    expect(existsSync(join(dir, "final-message.txt"))).toBe(false);
    const todo = JSON.parse(readFileSync(join(run, "council", "COUNCIL.todo.json"), "utf8"));
    expect(todo.candidates.length).toBeGreaterThan(0);
    // `db.ts:3` was resolved to `src/db.ts:3`: the todo keeps how it was written.
    const pw = todo.candidates.find((c: { title: string }) => /password committed/.test(c.title));
    expect(pw.citations[0]).toMatchObject({ at: "src/db.ts:3", raw: "db.ts:3", citation: "ok" });
  });

  it("finds the user's config at $XDG_CONFIG_HOME/ultrasec/council.json, and lists it in the plan", async () => {
    const repo = fixtureRepo();
    const run = fixtureRun(repo);
    const xdg = tmp("xdg");
    mkdirSync(join(xdg, "ultrasec"));
    writeConfig({ reviewers: { mycli: MYCLI } }, join(xdg, "ultrasec"));
    const count = { n: 0 };
    const plan = await council(["--run", run, "--repo", repo, "--json"], deps("/x", count, xdg));
    expect(count.n).toBe(0);
    const p = JSON.parse(plan.stdout);
    expect(p.config).toBe(join(xdg, "ultrasec", "council.json"));
    expect(p.reviewers.find((r: { reviewer: string }) => r.reviewer === "mycli")).toMatchObject({ source: "config", installed: false });
    const fake = fakeCli();
    const out = await council(["--run", run, "--repo", repo, "--models", "mycli:prov/x"], deps(fake.script, undefined, xdg));
    expect(out.result).toBe(0);
  });

  it("overrides a preset field by field, and `extends` derives a new entry", async () => {
    const repo = fixtureRepo();
    const run = fixtureRun(repo);
    const fake = fakeCli();
    const cfg = writeConfig({
      reviewers: {
        opencode: { modelPrefix: "gw/" },
        "oc-strict": { extends: "opencode", envPassthrough: ["COUNCIL_TEST_ALLOWED"] },
      },
    });
    process.env.COUNCIL_TEST_ALLOWED = "yes";
    process.env.COUNCIL_TEST_OTHER = "no";
    try {
      const out = await council(["--run", run, "--repo", repo, "--reviewer-config", cfg, "--models", "opencode:prov/a,oc-strict:prov/b"], deps(fake.script));
      expect(out.result).toBe(0);
    } finally {
      delete process.env.COUNCIL_TEST_ALLOWED;
      delete process.env.COUNCIL_TEST_OTHER;
    }
    const calls = fake.calls();
    const oc = calls.find((c) => c.args.includes("gw/prov/a"))!;
    expect(oc.args).toEqual(expect.arrayContaining(["--agent", "plan", "--pure"])); // the rest of the preset stays
    expect(oc.env.COUNCIL_TEST_ALLOWED).toBeUndefined();
    const strict = calls.find((c) => c.args.includes("prov/b"))!;
    expect(strict.env.COUNCIL_TEST_ALLOWED).toBe("yes");
    expect(strict.env.COUNCIL_TEST_OTHER).toBeUndefined();
    expect(
      loadLedger(run)!
        .reviewers.map((r) => r.name)
        .sort(),
    ).toEqual(["oc-strict", "opencode"]);
  });

  it("validates a config fail-closed", () => {
    const bad = (doc: unknown) => () => parseCouncilConfig(JSON.stringify(doc), "cfg.json");
    expect(bad({ reviewers: { x: { ...MYCLI, bni: "typo" } } })).toThrow(/unknown key "bni"/);
    expect(bad({ reviewers: { x: { ...MYCLI, readOnly: undefined } } })).toThrow(/"readOnly" is required/);
    expect(bad({ reviewers: { x: { ...MYCLI, args: ["{prompt}"] } } })).toThrow(/unknown placeholder \{prompt\}/);
    expect(bad({ reviewers: { x: { ...MYCLI, args: ["--out", "{outFile}"] } } })).toThrow(/must pass the brief/);
    expect(bad({ reviewers: { x: { ...MYCLI, events: "xml" } } })).toThrow(/expected one of/);
    expect(bad({ reviewers: { x: { ...MYCLI, quotaPatterns: ["("] } } })).toThrow(/invalid regex/);
    expect(bad({ reviewers: { "../x": MYCLI } })).toThrow(/reviewer name/);
    expect(bad({ reviewers: { x: { extends: "nope" } } })).toThrow(/unknown preset/);
    expect(bad({ placeholderPatterns: ["["] })).toThrow(/invalid placeholder pattern/);
  });

  it("refuses --resume of a reviewer whose entry is no longer defined", async () => {
    const repo = fixtureRepo();
    const run = fixtureRun(repo);
    const fake = fakeCli();
    const cfg = writeConfig({ reviewers: { mycli: MYCLI } });
    await council(["--run", run, "--repo", repo, "--reviewer-config", cfg, "--models", "mycli:prov/x"], deps(fake.script));
    const out = await council(["--run", run, "--resume", "mycli"], deps(fake.script));
    expect(out.result).toBe(2);
    expect(out.stderr).toMatch(/neither a preset nor in the reviewer config/);
  });
});

// ── Placeholders and locales ─────────────────────────────────────────────────

describe("masking placeholders", () => {
  it("flags generic shapes, and a custom pattern only when given", () => {
    expect(placeholderArtefacts("set to SCRUB_ab12cd34ef56 and REDACTED, or [redacted], or xxxxxxxx")).toEqual([
      "REDACTED",
      "SCRUB_ab12cd34ef…",
      "[redacted]",
      "xxxxxxxx",
    ]);
    expect(placeholderArtefacts("BUILD_20240101 and MAX_RETRIES are not placeholders")).toEqual([]);
    const custom = [/@@[A-Z0-9]{6,}@@/g];
    expect(placeholderArtefacts("token = @@AB12CD@@", custom)).toEqual(["@@AB12CD@@"]);
    expect(placeholderArtefacts("token = @@AB12CD@@")).toEqual([]);
    // Never redacted when known — the claim parser must still see it.
    expect(redactReviewerText("API_KEY=@@AB12CD34@@", custom)).toBe("API_KEY=@@AB12CD34@@");
    expect(redactReviewerText("API_KEY=@@AB12CD34@@")).not.toContain("AB12CD34");
  });

  it("a custom pattern from --placeholder-pattern flags the claim on --parse", async () => {
    const repo = fixtureRepo();
    const run = fixtureRun(repo);
    const fake = fakeCli();
    await council(["--run", run, "--repo", repo, "--models", "opencode:prov/a"], deps(fake.script));
    const before = JSON.parse(readFileSync(join(run, "council", "COUNCIL.todo.json"), "utf8"));
    const idor = (t: { candidates: { title: string; flags: string[] }[] }) => t.candidates.find((c) => /IDOR/.test(c.title))!;
    expect(idor(before).flags.join(" ")).not.toMatch(/placeholder/);
    const out = await council(["--run", run, "--parse", "--placeholder-pattern", "GET /invoice/\\d+"], deps(fake.script));
    expect(out.result).toBe(0);
    const after = JSON.parse(readFileSync(join(run, "council", "COUNCIL.todo.json"), "utf8"));
    expect(idor(after).flags.join(" ")).toMatch(/masking placeholder GET \/invoice\/2/);
    const badRe = await council(["--run", run, "--parse", "--placeholder-pattern", "("], deps(fake.script));
    expect(badRe.result).toBe(2);
  });
});

describe("locale headings", () => {
  const EN_DEVIL = [
    "## A. Contested findings",
    "",
    "### aaaaaaaaaaa1 — the query is not reachable unauthenticated",
    "- Proof: `src/app.ts:8` returns 401 first",
    "",
    "## B. New findings",
    "",
    "### D1 — Open redirect on /go",
    "- Severity: medium",
    "- CWE-601",
    "- Location: `src/app.ts:20`",
    "",
    "## C. Coverage",
    "- routes",
  ].join("\n");

  it("parses an English devil's-advocate report", () => {
    const claims = parseReport(EN_DEVIL, { reviewer: "r", phase: "devil" }, snapIndex());
    expect(claims.map((c) => [c.section, c.ref, c.severity ?? null])).toEqual([
      ["contest", "aaaaaaaaaaa1", null],
      ["new", "D1", "medium"],
    ]);
  });

  it("parses the headings each locale's brief asks for, in every locale", () => {
    const idx = snapIndex();
    for (const lang of LANGS) {
      const brief = renderBrief({ lang, phase: "devil", commit: "abc", devil: { items: [], rejected: [], truncated: 0 } });
      const headings = brief.split("\n").filter((l) => /^## [ABC]\. /.test(l));
      expect(headings, lang).toHaveLength(3);
      const report = [headings[0], "### aaaaaaaaaaa1 — wrong", headings[1], "### N1 — new one", "- `src/app.ts:20`", headings[2], "### not-a-claim"].join("\n");
      const claims = parseReport(report, { reviewer: "r", phase: "devil" }, idx);
      expect(
        claims.map((c) => [c.section, c.ref]),
        lang,
      ).toEqual([
        ["contest", "aaaaaaaaaaa1"],
        ["new", "N1"],
      ]);
      // Without the letters, the heading words alone still decide.
      const bare = report.replace(/^## [ABC]\. /gm, "## ");
      expect(
        parseReport(bare, { reviewer: "r", phase: "devil" }, idx).map((c) => c.section),
        lang,
      ).toEqual(["contest", "new"]);
    }
  });
});
