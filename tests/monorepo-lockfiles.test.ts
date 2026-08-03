import { describe, it, expect } from "vitest";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { findManifestDirs } from "../src/walk.js";
import { npmAudit, pnpmAudit, yarnAudit } from "../src/tools/pm-audit.js";
import { cargoAudit } from "../src/tools/cargo-audit.js";

// The package-manager audits used to gate on the ROOT lockfile alone, so every
// monorepo silently skipped them: on a repo with web/pnpm-lock.yaml and
// api/poetry.lock, `pnpm audit` reported "no pnpm-lock.yaml" — the same note a
// repo with no JavaScript at all would produce — while the vendored
// package-checker walked the tree and reported 49 advisories from those exact
// files. A coverage hole that reads as a clean result is the failure mode worth
// a regression test.

function repoWith(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), "ultrasec-mono-"));
  for (const [rel, body] of Object.entries(files)) {
    const abs = join(root, rel);
    mkdirSync(join(abs, ".."), { recursive: true });
    writeFileSync(abs, body);
  }
  return root;
}

const rels = (root: string, dirs: string[]) => dirs.map((d) => relative(root, d) || ".");

describe("findManifestDirs", () => {
  it("finds a manifest below the root, not just at it", () => {
    const root = repoWith({ "web/pnpm-lock.yaml": "", "README.md": "" });
    expect(rels(root, findManifestDirs(root, ["pnpm-lock.yaml"]))).toEqual(["web"]);
  });

  it("returns the root first, then deeper workspaces", () => {
    const root = repoWith({ "pnpm-lock.yaml": "", "packages/a/pnpm-lock.yaml": "", "packages/b/pnpm-lock.yaml": "" });
    expect(rels(root, findManifestDirs(root, ["pnpm-lock.yaml"]))).toEqual([".", "packages/a", "packages/b"]);
  });

  it("never descends into node_modules — a dependency's lockfile is not a workspace", () => {
    const root = repoWith({ "package-lock.json": "", "node_modules/left-pad/package-lock.json": "" });
    expect(rels(root, findManifestDirs(root, ["package-lock.json"]))).toEqual(["."]);
  });

  it("stops at the depth bound rather than walking an unbounded tree", () => {
    const root = repoWith({ "a/b/c/d/e/pnpm-lock.yaml": "" });
    expect(findManifestDirs(root, ["pnpm-lock.yaml"])).toEqual([]);
  });

  it("matches any of the accepted names", () => {
    const root = repoWith({ "app/npm-shrinkwrap.json": "" });
    expect(rels(root, findManifestDirs(root, ["package-lock.json", "npm-shrinkwrap.json"]))).toEqual(["app"]);
  });
});

describe("the package-manager audits apply in a monorepo", () => {
  const cases = [
    { name: "pnpm", adapter: pnpmAudit, file: "web/pnpm-lock.yaml" },
    { name: "npm", adapter: npmAudit, file: "packages/api/package-lock.json" },
    { name: "yarn", adapter: yarnAudit, file: "front/yarn.lock" },
    { name: "cargo", adapter: cargoAudit, file: "crates/core/Cargo.lock" },
  ];

  for (const c of cases) {
    it(`${c.name}: applicable when the lockfile is in a subdirectory`, () => {
      const root = repoWith({ [c.file]: "" });
      expect(c.adapter.applicable?.(root)).toBeNull();
      expect(rels(root, c.adapter.workspaces?.(root) ?? [])).toEqual([join(c.file, "..")]);
    });

    it(`${c.name}: the skip note says the subdirectories were checked too`, () => {
      const root = repoWith({ "README.md": "" });
      expect(c.adapter.applicable?.(root)).toMatch(/checked the root and its subdirectories/);
    });
  }
});
