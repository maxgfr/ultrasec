import { describe, it, expect } from "vitest";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { COMMAND_HANDLERS, HELP } from "../src/cli.js";
import { ALL_STAGES } from "../src/powered/pipeline.js";
import { VERSION } from "../src/types.js";

// Guards that the published SKILL.md stays installable via `npx skills add`.
// The skill is packaged under skills/ultrasec/ (not at the repo ROOT) so that
// `npx skills add` bundles the engine + references alongside the SKILL.md — a
// root SKILL.md would be installed ALONE (skills.sh early-returns the moment it
// sees one at the repo root, dropping sibling scripts/ and references/). See
// scripts/verify-skill-bundle.mjs for the install-bundle gate.
const ROOT = join(import.meta.dirname, "..");
const SKILL_DIR = join(ROOT, "skills", "ultrasec");
const FRONTMATTER_RE = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/;

const raw = readFileSync(join(SKILL_DIR, "SKILL.md"), "utf8");
const match = raw.match(FRONTMATTER_RE);
const frontmatter = match?.[1] ?? "";

// Pull a frontmatter scalar with the same regex the `skills` CLI / the
// verify-skill-bundle gate use, stripping surrounding quotes.
const field = (re: RegExp): string | undefined =>
  frontmatter
    .match(re)?.[1]
    ?.trim()
    .replace(/^["']|["']$/g, "");

describe("SKILL.md is installable by the `skills` CLI", () => {
  it("is packaged under skills/ultrasec/, not the repo root", () => {
    expect(existsSync(join(SKILL_DIR, "SKILL.md"))).toBe(true);
    // A root SKILL.md would make `skills add` install it alone, dropping the engine.
    expect(existsSync(join(ROOT, "SKILL.md"))).toBe(false);
  });

  it("has a frontmatter block", () => {
    expect(match).not.toBeNull();
    expect(frontmatter.length).toBeGreaterThan(0);
  });

  it("exposes the expected name", () => {
    expect(field(/^name:\s*(.+)$/m)).toBe("ultrasec");
  });

  it("exposes a non-empty description", () => {
    const desc = field(/^description:\s*(.+)$/m);
    expect(typeof desc).toBe("string");
    expect((desc ?? "").length).toBeGreaterThan(0);
  });

  // Claude Code caps skill descriptions at 1024 characters when matching a
  // request to a skill; a longer description risks truncation at the exact
  // moment the skill needs to be recognized. We budget at 1000 (mirrors
  // DESC_MAX in scripts/verify-skill-bundle.mjs) to keep a safety margin so a
  // future edit can't silently cross the cap.
  it("keeps the description within the 1000-char budget (headroom under the 1024 matcher limit)", () => {
    expect((field(/^description:\s*(.+)$/m) ?? "").length).toBeLessThanOrEqual(1000);
  });

  it("only references playbooks that exist on disk", () => {
    const mentioned = [...new Set(raw.match(/references\/[a-z0-9-]+\.md/g) ?? [])];
    expect(mentioned.length).toBeGreaterThan(0);
    for (const ref of mentioned) expect(existsSync(join(SKILL_DIR, ref)), `${ref} is mentioned in SKILL.md but missing`).toBe(true);
  });

  it("mentions every references/*.md playbook", () => {
    const files = readdirSync(join(SKILL_DIR, "references")).filter((f) => f.endsWith(".md"));
    expect(files.length).toBeGreaterThan(0);
    for (const f of files) expect(raw.includes(`references/${f}`), `references/${f} exists but SKILL.md never mentions it`).toBe(true);
  });

  it("keeps version in lockstep across SKILL.md, package.json and src/types.ts", () => {
    const metaVersion = field(/^\s+version:\s*(.+)$/m);
    const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as { version: string };
    expect(metaVersion).toBe(pkg.version);
    expect(VERSION).toBe(pkg.version);
  });

  // SKILL.md is loaded on EVERY invocation of the skill; references/ are loaded on
  // demand. Words that live here are paid for whether or not the run needs them, so
  // the body carries routing + the irreducible rules and the method goes to a
  // reference. Raising this cap is a real cost — log the reason when you do.
  //
  //   3183 -> 2400: `## The script` (148 lines duplicating `--help`) became a cheat
  //                 sheet + references/commands.md; six new references absorbed the
  //                 depth. Room was made for the run-health check, the symptom table,
  //                 Common mistakes / Do not, and the References index.
  //   2400 -> 2470: the body was sitting exactly at the cap, so the privacy dimension
  //                 could not be routed at all. Bought: the personal-data pointer in
  //                 rule 4 + the References index (the method itself is a reference,
  //                 not body), and three cheat-sheet lines for --report/--no-journal,
  //                 --strict and --no-env-sources. Routing, which is what the body is for.
  //   2470 -> 2760: four new judgment stages landed at once — `variants` (hunt the other
  //                 instances of a confirmed root cause), `assumptions` (what each function
  //                 trusts that nothing enforces), `coverage` (the ASVS map, so a short
  //                 report cannot read as "nothing there"), plus the agentic-CI and
  //                 sharp-edges lenses and the named grounds for a dismissal. A stage the
  //                 body never mentions is a stage nobody runs, so each bought exactly a
  //                 cheat-sheet line, a workflow step and a References entry — ~60 words
  //                 apiece. Every method stayed in references/. Do not spend the rest on prose.
  //   2760 -> 2820: the web-security expansion — the `access-control` investigate lens
  //                 (IDOR/BOLA/BFLA), pluggable `coverage --standard` packs (OWASP Top 10 /
  //                 API Top 10 / MASVS / CWE Top 25), and the isolated dynamic `probe`
  //                 command. A command the body never names is a command nobody runs, so
  //                 each bought a cheat-sheet line + a References entry; the web-misconfig
  //                 and auth-token detectors run under `scan` and are documented in
  //                 references/catalog.md, not the body. Methods stayed in references/.
  //   2820 -> 2860: closing the reverse-skill coverage gaps — the `route` command (triage
  //                 out-of-scope targets → external toolkit) and `logs --sigma` (SIEM
  //                 detection pack). Each bought a cheat-sheet line; `route` also a References
  //                 entry (route-playbook.md). The cloud/K8s detector runs under `scan` and
  //                 is documented in references/frameworks.md §Cloud, not the body.
  //   2860 -> 2975: the `guards` stage — the entry-point × auth-guard matrix. It is a new
  //                 workflow STEP, not another flag, and the one class the engine could not
  //                 reach at all: a missing authorization check has no line to taint-trace,
  //                 and on the audit it was built from that gap cost the three worst findings
  //                 in the repo. It buys a cheat-sheet line, one workflow step, one Common
  //                 mistake, and a `scan --include-vendored` mention. Everything else — the
  //                 row shape, the verdict vocabulary, what a marker does and does not prove —
  //                 went to references/schemas.md and references/commands.md.
  //   2975 -> 2997: two more absences the engine can now enumerate, both from the same
  //                 pair of real audits. `guards --lens throttle` — the handlers nothing
  //                 rate-limits, with the AUTH routes flagged apart (credential stuffing and
  //                 account enumeration, not capacity) — and `check` confronting CONTEXT.md's
  //                 negations with the code, because one sentence saying a class is not there
  //                 is how a class goes unexamined. Both are workflow-changing, so both buy a
  //                 clause in their step; the vocabulary, the CWE mapping, the precision rules
  //                 and the worked examples went to references/commands.md,
  //                 references/context-playbook.md and references/hunting-heuristics.md.
  //                 Paid for in part: five passages that duplicated a reference file or
  //                 repeated themselves were cut in the same change (-32 words).
  it("keeps the SKILL.md body within its word budget", () => {
    const words = (match?.[2] ?? "").split(/\s+/).filter(Boolean).length;
    expect(words, `SKILL.md body is ${words} words — move detail into references/ or raise the cap deliberately`).toBeLessThanOrEqual(2997);
  });

  // The engine lives at <skill-dir>/scripts/ultrasec.mjs. An installed skill sits
  // away from the user's project, so a cwd-relative invocation resolves to nothing —
  // and `orchestrate` fans work out to subagents that don't share our cwd at all.
  it("teaches the absolute-path convention and never models a relative one", () => {
    expect(raw, "SKILL.md must explain <skill-dir> resolution").toContain("<skill-dir>/scripts/ultrasec.mjs");
    expect(raw.includes("node scripts/ultrasec.mjs"), "SKILL.md models a cwd-relative engine path that fails for an installed skill").toBe(false);
  });

  // One canonical statement of what `run` sequences. It had drifted into three
  // mutually contradictory orderings (two in SKILL.md, one in powered-mode.md that
  // dropped `implement` entirely while the same file called it "the final stage").
  // Rule: the places that DO state it must state it identically, and nowhere may
  // state a different one.
  it("states the run stage list identically everywhere", () => {
    const canonical = ALL_STAGES.join(" → ");
    const powered = readFileSync(join(SKILL_DIR, "references", "powered-mode.md"), "utf8");
    const authorities = [
      ["references/powered-mode.md", powered],
      ["src/cli.ts HELP", HELP],
    ] as const;
    for (const [name, text] of authorities) {
      expect(text.replace(/\s+/g, " ").includes(canonical), `${name} must carry the canonical stage list "${canonical}"`).toBe(true);
    }
    // Any arrow-joined run of >=3 stage names anywhere in the docs must be the canonical one.
    const stageArrows = new RegExp(`(?:${ALL_STAGES.join("|")})(?: → (?:${ALL_STAGES.join("|")})){2,}`, "g");
    for (const f of readdirSync(join(SKILL_DIR, "references")).filter((n) => n.endsWith(".md"))) {
      const text = readFileSync(join(SKILL_DIR, "references", f), "utf8").replace(/\s+/g, " ");
      for (const m of text.matchAll(stageArrows)) {
        expect(m[0], `references/${f} states a stage ordering that isn't canonical`).toBe(canonical);
      }
    }
  });
});

// Docs that name a command or a flag the engine doesn't have are worse than no docs:
// the agent runs them and gets exit 2. `--help` is the authority, and these keep the
// prose pinned to it.
describe("SKILL.md and references stay in sync with the CLI", () => {
  const docs = [
    ["SKILL.md", raw],
    ...readdirSync(join(SKILL_DIR, "references"))
      .filter((f) => f.endsWith(".md"))
      .map((f) => [`references/${f}`, readFileSync(join(SKILL_DIR, "references", f), "utf8")] as const),
  ] as const;

  // Every flag any command actually reads, harvested from the real arg readers.
  const realFlags = (): Set<string> => {
    const found = new Set(["help", "version"]); // handled in main(), not via a flag reader
    const walk = (dir: string): void => {
      for (const e of readdirSync(dir, { withFileTypes: true })) {
        const p = join(dir, e.name);
        if (e.isDirectory()) {
          if (e.name !== "vendor") walk(p);
        } else if (p.endsWith(".ts") && !p.endsWith(".d.ts")) {
          for (const m of readFileSync(p, "utf8").matchAll(/\b(?:flagStr|flagBool|listFlag|numFlag)\(\s*\w+\s*,\s*["']([^"']+)["']/g)) {
            found.add(m[1] ?? "");
          }
        }
      }
    };
    walk(join(ROOT, "src"));
    return found;
  };

  // Only actual invocations count — a line inside a fenced block whose first token is
  // `ultrasec`. Prose that happens to say "ultrasec does X", and other tools' flags
  // quoted as examples (git's `--upload-pack`, docker's `--pull`), are not claims
  // about this CLI and must not be linted as if they were.
  const invocations = (text: string): string[] =>
    [...text.matchAll(/```[a-z]*\n([\s\S]*?)```/g)]
      .flatMap((b) => (b[1] ?? "").split("\n"))
      .map((l) => l.trim())
      .filter((l) => l.startsWith("ultrasec "));

  it("documents only commands the CLI dispatches", () => {
    const wired = new Set(Object.keys(COMMAND_HANDLERS));
    let checked = 0;
    for (const [name, text] of docs) {
      for (const line of invocations(text)) {
        const cmd = line.split(/\s+/)[1] ?? "";
        checked++;
        expect(wired.has(cmd), `${name} shows \`ultrasec ${cmd}\`, which no handler implements`).toBe(true);
      }
    }
    expect(checked, "found no ultrasec invocations to check — the extractor is broken").toBeGreaterThan(20);
  });

  it("documents only flags the engine reads", () => {
    const flags = realFlags();
    for (const [name, text] of docs) {
      for (const raw of invocations(text)) {
        // A quoted argument is opaque: `--agent "mytool exec {prompt} --cwd {run}"`
        // carries the OTHER CLI's flags, which ultrasec never parses.
        const line = raw.replace(/"[^"]*"|'[^']*'/g, '""');
        for (const m of line.matchAll(/--([a-z][a-z0-9-]+)/g)) {
          const flag = m[1] ?? "";
          expect(flags.has(flag), `${name} shows \`--${flag}\` on an ultrasec command line, but no command reads it`).toBe(true);
        }
      }
    }
  });
});
