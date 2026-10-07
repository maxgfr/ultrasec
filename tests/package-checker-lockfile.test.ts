import { afterEach, describe, expect, it } from "vitest";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mapExport } from "../src/tools/package-checker.js";
import { installedVersions } from "../src/tools/lockfile-versions.js";

// package-checker reads a manifest's RANGE as if it were an install: on a real
// monorepo it reported `next@16.2.11` critical from `"next": "^16.2.11"` in
// packages/app/package.json while pnpm-lock.yaml resolved only next@16.3.3. The
// version a finding names is now the one the lockfile installs, and when no
// lockfile says, the finding says the version is the declared range floor.

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
function repo(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "ultrasec-pc-lock-"));
  dirs.push(dir);
  for (const [rel, body] of Object.entries(files)) {
    mkdirSync(join(dir, rel, ".."), { recursive: true });
    writeFileSync(join(dir, rel), body);
  }
  return dir;
}

const PNPM_LOCK = `lockfileVersion: '9.0'

importers:

  .:
    devDependencies:
      typescript:
        specifier: ^5.5.0
        version: 5.6.3

  packages/app:
    dependencies:
      next:
        specifier: ^16.2.11
        version: 16.3.3(react-dom@19.1.0(react@19.1.0))(react@19.1.0)
      '@scope/lib':
        specifier: ~1.0.0
        version: 1.0.4

packages:

  next@16.3.3:
    resolution: {integrity: sha512-x}

  '@scope/lib@1.0.4':
    resolution: {integrity: sha512-y}
`;

const manifestHit = (pkg: string, version: string, file = "./packages/app/package.json") => ({
  vulnerabilities: [{ package: `${pkg}@${version}`, ghsa: "GHSA-2xp9-vwfh-vxw4", severity: "critical", ecosystem: "npm", source: "ghsa", file }],
});

describe("lockfile-resolved versions", () => {
  it("reads a pnpm workspace importer, peer suffix stripped", () => {
    const r = repo({ "pnpm-lock.yaml": PNPM_LOCK, "packages/app/package.json": JSON.stringify({ dependencies: { next: "^16.2.11" } }) });
    expect(installedVersions(r, "packages/app/package.json", "next")).toEqual({ lockfile: "pnpm-lock.yaml", versions: ["16.3.3"] });
    expect(installedVersions(r, "packages/app/package.json", "@scope/lib")?.versions).toEqual(["1.0.4"]);
  });

  it("reads package-lock.json v3 and yarn.lock", () => {
    const npm = repo({
      "package-lock.json": JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/next": { version: "16.3.3" } } }),
      "package.json": "{}",
    });
    expect(installedVersions(npm, "package.json", "next")?.versions).toEqual(["16.3.3"]);
    const yarn = repo({ "yarn.lock": `"next@^16.2.11":\n  version "16.3.3"\n  resolved "x"\n`, "package.json": "{}" });
    expect(installedVersions(yarn, "package.json", "next")?.versions).toEqual(["16.3.3"]);
  });
});

describe("package-checker manifest findings", () => {
  it("names the version the lockfile installs, not the range floor", () => {
    const r = repo({ "pnpm-lock.yaml": PNPM_LOCK, "packages/app/package.json": JSON.stringify({ dependencies: { next: "^16.2.11" } }) });
    const [f] = mapExport(manifestHit("next", "16.2.11"), r);
    expect(f!.version).toBe("16.3.3");
    expect(f!.versionSource).toBe("lockfile");
    expect(f!.message).toMatch(/declares `\^16\.2\.11`/);
    expect(f!.message).toMatch(/pnpm-lock\.yaml resolves 16\.3\.3/);
  });

  it("demotes a moved hit to info when the lockfile pass reported nothing for the installed version", () => {
    const r = repo({ "pnpm-lock.yaml": PNPM_LOCK, "packages/app/package.json": JSON.stringify({ dependencies: { next: "^16.2.11" } }) });
    const [phantom] = mapExport(manifestHit("next", "16.2.11"), r);
    expect(phantom!.severity).toBe("info");
    expect(phantom!.message).toMatch(/no GHSA-2xp9-vwfh-vxw4 for next@16\.3\.3/);
    // The same advisory also reported on the lockfile at 16.3.3: a real hit, severity kept.
    const both = mapExport(
      {
        vulnerabilities: [
          ...manifestHit("next", "16.2.11").vulnerabilities,
          { package: "next@16.3.3", ghsa: "GHSA-2xp9-vwfh-vxw4", severity: "critical", ecosystem: "npm", source: "ghsa", file: "./pnpm-lock.yaml" },
        ],
      },
      r,
    );
    expect(both.find((f) => f.versionSource === "lockfile")!.severity).toBe("critical");
  });

  it("reads an absolute manifest path the way the script reports it on a real run", () => {
    const r = repo({ "pnpm-lock.yaml": PNPM_LOCK, "packages/app/package.json": JSON.stringify({ dependencies: { next: "^16.2.11" } }) });
    const [f] = mapExport(manifestHit("next", "16.2.11", join(r, "packages/app/package.json")), r);
    expect(f!.version).toBe("16.3.3");
    expect(f!.message).toContain("packages/app/package.json declares `^16.2.11`");
    expect(f!.message).not.toContain(r);
  });

  it("marks the version as the declared range when no lockfile resolves the package", () => {
    const r = repo({ "packages/app/package.json": JSON.stringify({ dependencies: { next: "^16.2.11" } }) });
    const [f] = mapExport(manifestHit("next", "16.2.11"), r);
    expect(f!.version).toBe("16.2.11");
    expect(f!.versionSource).toBe("declared-range");
    expect(f!.message).toMatch(/declared range/);
  });

  it("leaves a finding alone when the lockfile installs the reported version, or when it cites the lockfile", () => {
    const r = repo({ "pnpm-lock.yaml": PNPM_LOCK, "packages/app/package.json": JSON.stringify({ dependencies: { next: "^16.2.11" } }) });
    const [same] = mapExport(manifestHit("next", "16.3.3"), r);
    expect(same!.version).toBe("16.3.3");
    expect(same!.versionSource).toBeUndefined();
    const [lock] = mapExport(manifestHit("next", "16.3.3", "./pnpm-lock.yaml"), r);
    expect(lock!.versionSource).toBeUndefined();
  });

  it("without a repo the mapping is unchanged", () => {
    const [f] = mapExport(manifestHit("next", "16.2.11"));
    expect(f!.version).toBe("16.2.11");
    expect(f!.versionSource).toBeUndefined();
  });
});
