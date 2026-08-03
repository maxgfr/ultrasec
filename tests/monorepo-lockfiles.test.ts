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

// The bug this section exists to prevent: the first implementation re-anchored
// findings AFTER the adapter had built them, so every citation kept the
// workspace-relative name. On a repo whose only lockfile is web/pnpm-lock.yaml,
// 62 real advisories all cited `pnpm-lock.yaml` at the root — a path that does
// not exist — and `ultrasec check` failed the grounding gate on all of them.
// Worse, the finding id is derived from that path, so two workspaces carrying
// the same advisory collapsed onto one id.
describe("workspace findings cite a path that actually resolves", () => {
  const advisory = (id: string) =>
    JSON.stringify({
      advisories: {
        [id]: {
          module_name: "left-pad",
          findings: [{ version: "1.0.0" }],
          severity: "high",
          title: "Prototype pollution",
          url: "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
          github_advisory_id: "GHSA-aaaa-bbbb-cccc",
        },
      },
    });

  it("prefixes the lockfile with the workspace, so the citation resolves", () => {
    const findings = pnpmAudit.parse(advisory("1"), "/repo", { workspace: "web" });
    expect(findings.map((f) => f.sink?.file)).toEqual(["web/pnpm-lock.yaml"]);
  });

  it("leaves the root case untouched", () => {
    expect(pnpmAudit.parse(advisory("1"), "/repo", {})[0]!.sink?.file).toBe("pnpm-lock.yaml");
    expect(pnpmAudit.parse(advisory("1"), "/repo")[0]!.sink?.file).toBe("pnpm-lock.yaml");
  });

  it("gives the SAME advisory in two workspaces two distinct ids", () => {
    const a = pnpmAudit.parse(advisory("1"), "/repo", { workspace: "web" })[0]!;
    const b = pnpmAudit.parse(advisory("1"), "/repo", { workspace: "admin" })[0]!;
    expect(a.sink?.file).toBe("web/pnpm-lock.yaml");
    expect(b.sink?.file).toBe("admin/pnpm-lock.yaml");
    // Ids are content-derived from the cited path; colliding here would make the
    // two indistinguishable to verify/dossier and let one overwrite the other.
    expect(a.id).not.toBe(b.id);
  });

  it("applies to yarn and cargo too", () => {
    const yarn = yarnAudit.parse(
      JSON.stringify({ type: "auditAdvisory", data: { advisory: { id: 1, module_name: "x", findings: [{ version: "1" }], severity: "low", title: "t" } } }),
      "/repo",
      {
        workspace: "front",
      },
    );
    expect(yarn[0]!.sink?.file).toBe("front/yarn.lock");

    const cargo = cargoAudit.parse(
      JSON.stringify({ vulnerabilities: { list: [{ advisory: { id: "RUSTSEC-2021-0001", title: "t" }, package: { name: "p", version: "1" } }] } }),
      "/repo",
      {
        workspace: "crates/core",
      },
    );
    expect(cargo[0]!.sink?.file).toBe("crates/core/Cargo.lock");
  });
});
