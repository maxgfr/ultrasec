#!/usr/bin/env node
// Regenerate assets/example-audit/ — the complete, committed run a reader can inspect
// without executing anything.
//
// It used to be produced by hand, and it drifted: the committed manifest sat at
// schemaVersion 4 while the engine moved to 6, it carried a `FULL.md` no `render` has
// emitted in years, and its NARRATIVE.json pasted the command-injection remediation
// onto the XSS finding. A canonical example that teaches a wrong fix is worse than no
// example, so it is generated now, and `--check` fails CI when it is stale.
//
// The AUTHORED inputs (the parts a human/AI writes) stay under version control in
// assets/example-audit/ and are fed back in: CONTEXT.md, verdicts.json,
// REVALIDATE.json, NARRATIVE.json. Everything else is engine output.
//
// Pure Node, no deps, no network (`--tools none --offline`).
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, sep } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const engine = join(root, "scripts", "ultrasec.mjs");
const outDir = join(root, "assets", "example-audit");
const fixture = join(root, "tests", "fixtures", "vuln-express");
const check = process.argv.includes("--check");

// The example presents the fixture as if it lived at `examples/vuln-express`, and pins
// the version, so a release bump doesn't churn every artifact.
const SANITIZED_REPO = "examples/vuln-express";
const SANITIZED_VERSION = "0.0.0-development";
const AUTHORED = ["CONTEXT.md", "verdicts.json", "REVALIDATE.json", "NARRATIVE.json"];
// Everything the pipeline emits, in the order the README documents them.
const GENERATED = [
  "manifest.json",
  "findings.json",
  "graph.json",
  "DOSSIER.md",
  "VERIFY.todo.json",
  "VERIFY.md",
  "REVALIDATE.todo.json",
  "REVALIDATE.md",
  "NARRATIVE.todo.json",
  "NARRATIVE.md",
  "SUMMARY.md",
  "REPORT.md",
  "index.html",
  "IMPLEMENT.md",
  "IMPLEMENT.todo.json",
];

// realpath, because the engine resolves every path it records — on macOS a bare
// mkdtemp path is /var/folders/… while its realpath is /private/var/folders/…, and
// sanitizing only one of the two leaves a "/private" stub in the committed manifest.
const tmp = realpathSync(mkdtempSync(join(tmpdir(), "ultrasec-example-")));
const repo = join(tmp, "examples", "vuln-express");
const run = join(tmp, "run");

// Hermetic git: the developer's global/system config must not reach this repo. With
// `commit.gpgsign = true` set globally — common — every commit embeds a fresh
// signature timestamp and the sha differs on every run, so the emitted revalidation
// facts would never be reproducible.
const GIT_ENV = { ...process.env, GIT_TERMINAL_PROMPT: "0", GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null" };
const git = (...args) => execFileSync("git", ["-C", repo, ...args], { stdio: "pipe", env: GIT_ENV });
const ultrasec = (...args) => execFileSync(process.execPath, [engine, ...args], { cwd: tmp, stdio: "pipe" }).toString();

try {
  mkdirSync(dirname(repo), { recursive: true });
  // Copy the SOURCE of the fixture only. The fixture carries a package.json, so a
  // recursive pnpm operation at the repo root treats it as a second workspace
  // project and drops a `node_modules/.modules.yaml` in it. That directory is
  // gitignored here but NOT in the throwaway repo below, where `git add -A` would
  // sweep it into the tree — changing the commit sha, and with it the `commit`
  // field `revalidate` records. The result: `--check` reports REVALIDATE.* stale
  // for a reason that has nothing to do with the engine, on whichever machine
  // happened to run an install. Filtering here keeps the promise the comment below
  // makes — identical output on every machine and every run.
  cpSync(fixture, repo, { recursive: true, filter: (src) => !src.split(sep).includes("node_modules") });

  // `revalidate` reads git history. A fixed author and date keep the emitted facts
  // (commit sha, author, date) identical on every machine and every run.
  git("init", "-q", "-b", "main");
  git("config", "user.name", "ultrasec example");
  git("config", "user.email", "example@ultrasec.invalid");
  git("config", "commit.gpgsign", "false");
  git("add", "-A");
  execFileSync("git", ["-C", repo, "commit", "-q", "-m", "example fixture"], {
    stdio: "pipe",
    env: { ...GIT_ENV, GIT_AUTHOR_DATE: "2026-01-15T00:00:00Z", GIT_COMMITTER_DATE: "2026-01-15T00:00:00Z" },
  });

  mkdirSync(run, { recursive: true });
  // CONTEXT.md must be in place before any worklist is emitted — every stage reasons with it.
  writeFileSync(join(run, "CONTEXT.md"), readFileSync(join(outDir, "CONTEXT.md"), "utf8"));

  ultrasec("scan", "--repo", SANITIZED_REPO, "--out", "run", "--tools", "none", "--offline");
  ultrasec("verify", "--run", "run");
  writeFileSync(join(run, "verdicts.json"), readFileSync(join(outDir, "verdicts.json"), "utf8"));
  ultrasec("verify", "--apply", join(run, "verdicts.json"), "--run", "run");
  ultrasec("revalidate", "--run", "run", "--repo", SANITIZED_REPO);
  writeFileSync(join(run, "REVALIDATE.json"), readFileSync(join(outDir, "REVALIDATE.json"), "utf8"));
  ultrasec("revalidate", "--apply", join(run, "REVALIDATE.json"), "--run", "run", "--repo", SANITIZED_REPO);
  ultrasec("check", "--run", "run", "--repo", SANITIZED_REPO, "--semantic");
  ultrasec("narrative", "--run", "run");
  writeFileSync(join(run, "NARRATIVE.json"), readFileSync(join(outDir, "NARRATIVE.json"), "utf8"));
  ultrasec("render", "--run", "run", "--narrative", join(run, "NARRATIVE.json"));
  ultrasec("implement", "--run", "run", "--narrative", join(run, "NARRATIVE.json"));

  const sanitize = (s) =>
    s
      .split(repo)
      .join(SANITIZED_REPO)
      .split(tmp)
      .join(SANITIZED_REPO)
      .split(`ultrasec ${readFileSync(join(root, "package.json"), "utf8").match(/"version":\s*"([^"]+)"/)[1]}`)
      .join(`ultrasec ${SANITIZED_VERSION}`)
      .split(`"version": "${JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version}"`)
      .join(`"version": "${SANITIZED_VERSION}"`);

  const stale = [];
  for (const name of GENERATED) {
    const src = join(run, name);
    if (!existsSync(src)) throw new Error(`the pipeline did not produce ${name}`);
    const next = sanitize(readFileSync(src, "utf8"));
    const dest = join(outDir, name);
    const prev = existsSync(dest) ? readFileSync(dest, "utf8") : null;
    if (prev !== next) stale.push(name);
    if (!check) writeFileSync(dest, next);
  }

  // Artifacts an older engine produced that nothing emits any more.
  const known = new Set([...AUTHORED, ...GENERATED, "README.md"]);
  const orphans = readdirSync(outDir).filter((f) => !known.has(f));
  if (!check) for (const f of orphans) rmSync(join(outDir, f), { force: true });

  if (check) {
    const problems = [...stale.map((f) => `stale: ${f}`), ...orphans.map((f) => `orphan: ${f}`)];
    if (problems.length) {
      console.error("build-example-audit --check FAILED:\n  " + problems.join("\n  ") + "\n\nRun: node scripts/build-example-audit.mjs");
      process.exit(1);
    }
    console.log("build-example-audit: assets/example-audit is up to date");
  } else {
    console.log(`build-example-audit: wrote ${GENERATED.length} artifact(s) to assets/example-audit${orphans.length ? ` (removed ${orphans.length} orphan(s): ${orphans.join(", ")})` : ""}`);
  }
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
