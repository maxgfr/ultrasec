import { describe, it, expect } from "vitest";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
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
});
