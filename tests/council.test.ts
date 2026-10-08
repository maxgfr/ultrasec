import { afterEach, describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runCouncilWith, type CouncilDeps } from "../src/commands/council.js";
import { ADAPTERS, parseModelList, reviewersFrom } from "../src/council/adapters.js";
import { applyCouncil, parseDecisions } from "../src/council/apply.js";
import { argvMessage, buildDevilList, renderBrief } from "../src/council/brief.js";
import { indexTree, parseReport, type Claim } from "../src/council/claims.js";
import { consolidate, cweFamily } from "../src/council/consolidate.js";
import { classifyFailure, digestOpencode, isContractShaped } from "../src/council/events.js";
import { loadLedger } from "../src/council/ledger.js";
import { placeholderArtefacts, redactJsonLine, redactReviewerText } from "../src/council/redact.js";
import type { CouncilSpawner } from "../src/council/runner.js";
import { councilEnv, createSnapshot, snapshotFiles } from "../src/council/snapshot.js";
import { countBySeverity, loadDossier, writeDossier } from "../src/store.js";
import type { Finding } from "../src/types.js";
import { captureOutput, parseArgs } from "../src/util.js";

// Every test here runs against SYNTHETIC fixtures and a fake CLI (a node
// script standing in for opencode/kilo/vibe through the adapter command
// override). No real reviewer CLI and no network is ever touched.

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
  "- Evidence: JWT_SECRET is set to SECRETGATE_9f3a2b1c in production config",
  "",
  "### R5 — SQL injection in search",
  "- Severity: high",
  "- CWE: CWE-89",
  "- Location: `src/app.ts:16`",
  "",
  "## To verify",
  "- tar-fs 2.1.2 is the fixed version",
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
 * The fake CLI: one node script standing in for opencode/kilo (JSON events) and
 * vibe (text). Its behaviour is keyed on the model name, and every call is
 * logged — argv, env, cwd — to a file OUTSIDE the snapshot.
 */
function fakeCli(): { script: string; log: string; calls: () => { args: string[]; env: Record<string, string>; cwd: string; brief: string | null }[] } {
  const dir = tmp("fake");
  const log = join(dir, "calls.jsonl");
  const script = join(dir, "fake-cli.mjs");
  const reports = { a: REPORT_A, b: REPORT_B, devil: REPORT_DEVIL };
  writeFileSync(
    script,
    `
import { appendFileSync, existsSync, readFileSync } from "node:fs";
const REPORTS = ${JSON.stringify(reports)};
const args = process.argv.slice(2);
const val = (f) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : undefined; };
const text = args.includes("-p");
const pointed = (text ? val("-p") : args[args.length - 1]).match(/_COUNCIL_BRIEF[\\w.-]+\\.md/)?.[0];
const brief = pointed && existsSync(pointed) ? readFileSync(pointed, "utf8") : null;
appendFileSync(${JSON.stringify(log)}, JSON.stringify({ args, env: process.env, cwd: process.cwd(), brief }) + "\\n");
const model = val("-m") ?? process.env.VIBE_ACTIVE_MODEL ?? "";
const session = val("-s");
const msg = text ? val("-p") : args[args.length - 1];
const key = model.split("/").pop();
const sid = session ?? "ses_" + key.replace(/\\W/g, "");
const ev = (o) => process.stdout.write(JSON.stringify({ sessionID: sid, ...o }) + "\\n");
const step = (cost) => ev({ type: "step_finish", part: { type: "step-finish", tokens: { input: 1000, output: 200, reasoning: 50, cache: { read: 300, write: 10 } }, cost } });
const say = (t, m) => ev({ type: "text", part: { type: "text", messageID: m, text: t } });
if (text) { process.stdout.write(REPORTS[key] ?? ""); process.exit(0); }
const finalizing = !!session && /Stop exploring|Arrêtez/.test(msg);
ev({ type: "step_start", part: { type: "step-start" } });
if (model.includes("504")) {
  ev({ type: "error", error: { name: "APIError", data: { message: "Upstream idle timeout", statusCode: 504 } } });
  process.exit(1);
}
if (finalizing) { say(REPORTS[model.includes("notes") || model.includes("pricey") ? "b" : "a"], "m9"); step(0.001); process.exit(0); }
if (model.includes("quota")) {
  say("Reading the invoice router first.", "m1");
  step(0.005);
  ev({ type: "error", error: { name: "APIError", data: { message: "Usage limit reached for 5 hour. Your limit will reset at 2026-10-09 01:52:02", statusCode: 429, responseBody: '{"error":{"code":"1308"}}' } } });
  process.exit(1);
}
if (model.includes("credit")) {
  ev({ type: "error", error: { error_type: "usage_limit_exceeded", message: "Low Credit Warning: balance exhausted" } });
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

function deps(script: string, spawnCount?: { n: number }): CouncilDeps {
  const prefix = [process.execPath, script];
  return {
    commands: { opencode: prefix, kilo: prefix, vibe: prefix },
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
    // The read-only agent, without external plugins (the Sisyphus stall).
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
  it("quota → resumes the SAME session for one turn on the fallback chain, past a 504", async () => {
    const repo = fixtureRepo();
    const run = fixtureRun(repo);
    const fake = fakeCli();
    const out = await council(
      ["--run", run, "--repo", repo, "--models", "kilo:prov/quota", "--fallback", "kilo:kilo/free-504,kilo:kilo-auto/free-ok"],
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
    expect(calls[1]!.args).toContain("kilo/free-504");
    expect(calls[2]!.args).toContain("kilo/kilo-auto/free-ok");
    const rec = loadLedger(run)!.reviewers[0]!;
    expect(rec.attempts.map((a) => a.status)).toEqual(["quota", "upstream", "ok"]);
    expect(rec.status).toBe("ok");
  });

  it("quota with no fallback → recorded with the reset time; `--resume` finalises it later", async () => {
    const repo = fixtureRepo();
    const run = fixtureRun(repo);
    const fake = fakeCli();
    const first = await council(["--run", run, "--repo", repo, "--models", "opencode:zai/quota"], deps(fake.script));
    expect(first.result).toBe(1);
    let rec = loadLedger(run)!.reviewers[0]!;
    expect(rec.status).toBe("quota");
    expect(rec.resetAt).toBe("2026-10-09 01:52:02");
    expect(first.stdout).toMatch(/quota resets at 2026-10-09 01:52:02/);

    const again = await council(["--run", run, "--resume", "opencode"], deps(fake.script));
    expect(again.result).toBe(0);
    expect(again.stdout).toMatch(/resets at 2026-10-09 01:52:02/);
    const last = fake.calls().at(-1)!;
    expect(last.args).toEqual(expect.arrayContaining(["-s", "ses_quota", "-m", "zai/quota"]));
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

  it("an unknown CLI in --models fails closed", async () => {
    const repo = fixtureRepo();
    const run = fixtureRun(repo);
    const out = await council(["--run", run, "--repo", repo, "--models", "gemini:pro"], deps("/x", { n: 0 }));
    expect(out.result).toBe(2);
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
    const d = digestOpencode(lines.map((l) => JSON.stringify(l)).join("\n"));
    expect(d.session).toBe("ses_1");
    expect(d.text).toBe("### R1 — x");
    expect(d.usage).toMatchObject({ input: 20, output: 10, reasoning: 2, cacheRead: 4, cacheWrite: 6, steps: 2 });
    expect(d.usage.cost).toBeCloseTo(0.3);
  });

  it("classifies the real stop messages", () => {
    expect(classifyFailure("Usage limit reached for 5 hour. Your limit will reset at 2026-10-09 01:52:02")).toMatchObject({
      kind: "quota",
      resetAt: "2026-10-09 01:52:02",
    });
    expect(classifyFailure('{"code":1308,"message":"limit"}').kind).toBe("quota");
    expect(classifyFailure('{"error_type":"usage_limit_exceeded"}').kind).toBe("credit");
    expect(classifyFailure("Low Credit Warning").kind).toBe("credit");
    expect(classifyFailure("504 Upstream idle timeout").kind).toBe("upstream");
    expect(classifyFailure("TypeError: boom").kind).toBe("error");
  });

  it("a report is contract-shaped; progress notes are not", () => {
    expect(isContractShaped("### R1 — t")).toBe(true);
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
    expect(r4.artefacts).toEqual(["SECRETGATE_9f3a2…"]);
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
      "### R1 — vulnerable tar-fs\n- Severity: high\n- `src/app.ts:1` tar-fs 2.1.2 is the fixed version (CVE-2024-12905)",
      { reviewer: "x", phase: "blind" },
      idx,
    );
    expect(c!.verify.join(" ")).toMatch(/osv\/trivy/);
    expect(c!.cves).toEqual(["CVE-2024-12905"]);
  });
});

// ── Redaction ────────────────────────────────────────────────────────────────

describe("redaction", () => {
  it("masks a modular-crypt hash, NAME=secret, quoted secrets, JWTs and long tokens", () => {
    const s = redactReviewerText(
      [
        "hash $argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo",
        "HASURA_GRAPHQL_ADMIN_SECRET=adminsecret123",
        `"jwt_secret": "my-very-secret"`,
        "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.c2lnbmF0dXJlLXZhbHVl",
        "key a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
      ].join("\n"),
    );
    expect(s).toContain("$argon2id$v=19$m=65536,t=3,p=4$…");
    expect(s).not.toContain("aGFzaGhhc2hoYXNo");
    expect(s).toContain("HASURA_GRAPHQL_ADMIN_SECRET=admi…");
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
      { id: find(/JWT secret/), decision: "reject", reason: "SECRETGATE is our own masking hook" },
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
      ["orchestrator", "SECRETGATE is our own masking hook"],
      ["citation-gate", expect.stringMatching(/^line out of range: src\/db\.ts:999/)],
    ]);
    expect(out.stdout).toMatch(/no resolvable citation/); // the invented-line candidate is refused
    expect(out.stdout).toMatch(/a reject must say why/);
    expect(out.stdout).toMatch(/contestation\(s\) stay a worklist/);
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

describe("adapters", () => {
  it("splits cli:model on the first colon only (kilo free models end in :free)", () => {
    expect(parseModelList("kilo:openrouter/x:free,opencode:a/b", "--models")).toEqual([
      { cli: "kilo", model: "openrouter/x:free" },
      { cli: "opencode", model: "a/b" },
    ]);
    expect(reviewersFrom(parseModelList("kilo:a,kilo:b", "--models")).map((r) => r.name)).toEqual(["kilo", "kilo-2"]);
  });

  it("codex and vibe cannot resume a session they never named", () => {
    const i = { model: "m", dir: "/s", message: "x", title: "t", maxTurns: 5 };
    expect(ADAPTERS.codex.resume({ ...i, session: "s" })).toBeNull();
    expect(ADAPTERS.vibe.resume(i)).toBeNull();
    expect(ADAPTERS.codex.start(i)).toEqual(expect.arrayContaining(["--sandbox", "read-only", "--skip-git-repo-check"]));
  });
});
