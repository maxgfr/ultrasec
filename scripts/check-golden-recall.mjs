#!/usr/bin/env node
// Recall guard for a regenerated golden set.
//
// `tests/golden/*.json` is ENGINE OUTPUT: a new codeindex version legitimately
// changes what the walk records (v2.20.1 -> v2.27.1, for instance, added the
// enclosing `symbol` to every path step). So the automatic engine re-pin has to
// regenerate them — but regenerating a regression gate on autopilot destroys the
// very thing it guards: an engine upgrade that silently stopped finding a class
// of bugs would be committed as the new "expected" output and pushed to main.
//
// This is the guard that keeps the signal. It compares the regenerated goldens in
// the working tree against the committed ones and fails when a fixture's finding
// count DROPS. Added findings and changed metadata pass (that is enrichment);
// losing one is a human decision, never an automatic push.
//
// Counts, not ids: finding ids are content-derived, so a legitimate change (a
// line number moving) rewrites them. The count is the recall signal — "a degraded
// run must never pass for a full one", the same rule the engine applies to itself.
//
// Usage: node scripts/check-golden-recall.mjs [--ref HEAD]
// Exit 0 = no recall lost · 1 = a fixture lost findings · 2 = usage/runtime error.
import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const goldenDir = join(root, "tests", "golden");
const refIdx = process.argv.indexOf("--ref");
const ref = refIdx === -1 ? "HEAD" : (process.argv[refIdx + 1] ?? "HEAD");

/** The committed version of a golden, or null when it is new in this tree. */
function committed(rel) {
  try {
    return JSON.parse(execFileSync("git", ["show", `${ref}:${rel}`], { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }));
  } catch {
    return null; // not in the ref: a brand-new fixture, nothing to lose yet
  }
}

const count = (g) => (Array.isArray(g?.findings) ? g.findings.length : 0);

let files;
try {
  files = readdirSync(goldenDir)
    .filter((f) => f.endsWith(".json"))
    .sort();
} catch (e) {
  console.error(`check-golden-recall: cannot read ${goldenDir} (${e.message})`);
  process.exit(2);
}

const lost = [];
const gained = [];
let added = 0;
let total = 0;

for (const f of files) {
  const rel = `tests/golden/${f}`;
  const before = committed(rel);
  if (before === null) {
    added++;
    continue;
  }
  let after;
  try {
    after = JSON.parse(readFileSync(join(goldenDir, f), "utf8"));
  } catch (e) {
    console.error(`check-golden-recall: ${rel} is unreadable or invalid JSON (${e.message})`);
    process.exit(2);
  }
  const b = count(before);
  const a = count(after);
  total += a;
  if (a < b) lost.push({ rel, before: b, after: a });
  else if (a > b) gained.push({ rel, before: b, after: a });
}

if (lost.length) {
  console.error(`check-golden-recall: RECALL LOST in ${lost.length} fixture(s) — refusing to accept the regenerated goldens.`);
  for (const l of lost) console.error(`  ${l.rel}: ${l.before} -> ${l.after} finding(s)`);
  console.error("");
  console.error("The engine now finds FEWER issues on a fixture whose code did not change.");
  console.error("That is a recall regression, not enrichment: review it by hand before re-pinning.");
  process.exit(1);
}

const parts = [`${files.length - added} fixture(s) compared vs ${ref}`, `${total} finding(s)`];
if (gained.length) parts.push(`${gained.length} fixture(s) gained findings`);
if (added) parts.push(`${added} new fixture(s) skipped`);
console.log(`check-golden-recall: ok — no recall lost (${parts.join(", ")}).`);
