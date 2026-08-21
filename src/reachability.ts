import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { findManifestDirs } from "./walk.js";
import type { Finding } from "./types.js";

// Which dependency advisories are about code that SHIPS, and which are about the
// toolchain that builds it.
//
// A dependency scanner answers "is this CVE present in the tree?". It does not
// answer "is it in the artifact?", and on a real audit that gap dominated the
// top of the report: build-only advisories with EPSS around 1 % were rated
// `critical` beside genuine runtime exposure, and an auditor spent the first
// hour taking them apart. `handlebars` reached through `ts-jest` is a real CVE
// in a real installed package, and it is not a way into production.
//
// This is EVIDENCE, not a verdict. A `toolchain` mark damps the composite risk
// (see `REACHABILITY_DAMP`) and says so in the report; it never dismisses a
// finding, and an auditor who knows the build output is served — a bundler that
// inlines a dev dependency, a test fixture shipped in the image — confirms it
// anyway.
//
// ── What this pass does and does not know ──────────────────────────────────
//
// It is deliberately built from facts already on disk, with no lockfile
// dependency graph:
//
//   • `package-lock.json` (v2/v3) marks EVERY entry it installs, transitive
//     ones included, with `"dev": true`. That is exact, free, and covers the
//     `handlebars`-under-`ts-jest` shape that motivated the whole thing.
//   • Every `package.json` in the tree names its DIRECT `devDependencies`. That
//     works for any JS package manager, but only one level deep.
//
// So on npm the classification reaches transitives; on pnpm and yarn it reaches
// direct dev dependencies only, and a transitive dev-only package is left
// UNMARKED. Unmarked means undamped — the conservative direction. This pass will
// never quietly de-prioritize a runtime CVE because it failed to see something;
// it under-claims instead, and `manifest.reachability` reports which sources it
// actually had.
//
// It also never marks anything `runtime`. "Not known to be dev-only" is not the
// same fact, and writing it down as one would be exactly the overreach this
// module exists to avoid.

const NPM_LOCKFILES = ["package-lock.json", "npm-shrinkwrap.json"] as const;

/** How a package name is spelled inside a `package-lock.json` packages key. */
function packageNameFromLockKey(key: string): string | undefined {
  // "node_modules/foo", "node_modules/@scope/foo",
  // "node_modules/a/node_modules/b" → the LAST segment after node_modules/.
  const at = key.lastIndexOf("node_modules/");
  if (at === -1) return undefined;
  const name = key.slice(at + "node_modules/".length);
  return name.length ? name : undefined;
}

interface LockEntry {
  dev?: boolean;
  devOptional?: boolean;
}

/**
 * Package names this repo installs ONLY for development, and the sources the
 * answer came from.
 *
 * A name is dev-only when every place it appears says so. One runtime use
 * anywhere in a monorepo makes it runtime — a package shipped by one workspace
 * is shipped, whatever the others use it for.
 */
export function devOnlyPackages(repo: string): { names: Set<string>; sources: string[] } {
  const devSeen = new Set<string>();
  const runtimeSeen = new Set<string>();
  const sources: string[] = [];

  // 1. npm lockfiles — transitive, exact.
  for (const dir of findManifestDirs(repo, NPM_LOCKFILES)) {
    for (const file of NPM_LOCKFILES) {
      const path = join(dir, file);
      if (!existsSync(path)) continue;
      let lock: { packages?: Record<string, LockEntry> };
      try {
        lock = JSON.parse(readFileSync(path, "utf8")) as { packages?: Record<string, LockEntry> };
      } catch {
        continue; // an unreadable lockfile is not a reason to fail the audit
      }
      if (!lock.packages) continue; // v1 lockfile: no per-entry dev flag
      sources.push(file);
      for (const [key, entry] of Object.entries(lock.packages)) {
        const name = packageNameFromLockKey(key);
        if (!name) continue;
        // `devOptional` means "dev in one branch, optional in another" — not a
        // guarantee it stays out of the artifact, so it counts as runtime.
        if (entry?.dev === true && entry?.devOptional !== true) devSeen.add(name);
        else runtimeSeen.add(name);
      }
    }
  }

  // 2. Every package.json's DIRECT declarations — any package manager, one level.
  const manifestDirs = findManifestDirs(repo, ["package.json"]);
  if (manifestDirs.length) sources.push("package.json");
  for (const dir of manifestDirs) {
    let pkg: { dependencies?: Record<string, string>; devDependencies?: Record<string, string>; optionalDependencies?: Record<string, string> };
    try {
      pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
    } catch {
      continue;
    }
    for (const name of Object.keys(pkg.devDependencies ?? {})) devSeen.add(name);
    for (const name of Object.keys(pkg.dependencies ?? {})) runtimeSeen.add(name);
    for (const name of Object.keys(pkg.optionalDependencies ?? {})) runtimeSeen.add(name);
  }

  const names = new Set([...devSeen].filter((n) => !runtimeSeen.has(n)));
  return { names, sources: [...new Set(sources)].sort() };
}

/**
 * Mark dependency advisories whose package is installed for the build only.
 *
 * Scoped to `category === "dep"`: this is a statement about a PACKAGE, and a
 * SAST hit or a secret in a dev tool is a different claim with a different
 * answer. Findings already carrying a `reachability` are left alone — a more
 * specific pass (`govulncheck`'s real call-graph reachability, an auditor's
 * verdict) outranks a manifest lookup.
 */
export function classifyDependencyReachability(findings: Finding[], repo: string): { findings: Finding[]; toolchain: number; sources: string[] } {
  const { names, sources } = devOnlyPackages(repo);
  if (!names.size) return { findings, toolchain: 0, sources };

  let toolchain = 0;
  const out = findings.map((f) => {
    if (f.category !== "dep" || f.reachability || !f.pkg || !names.has(f.pkg)) return f;
    toolchain++;
    return { ...f, reachability: "toolchain" as const };
  });
  return { findings: out, toolchain, sources };
}
