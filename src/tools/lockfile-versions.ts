import { existsSync, readFileSync } from "node:fs";
import { dirname, join, posix, relative, sep } from "node:path";

// Which version of a package a JavaScript lockfile actually installs for one
// manifest — so a dependency finding cited on `package.json` can name it.
//
// A manifest carries a RANGE. A scanner that reads `"next": "^16.2.11"` as
// next@16.2.11 reports an advisory against a version that may not be installed
// anywhere: on a real monorepo that was a critical for next@16.2.11 while the
// lockfile resolved only 16.3.3. The lockfile is the fact; this reads it.
//
// Line-oriented on purpose (no YAML dependency may enter the bundle), and narrow:
// pnpm (importers, then package keys), npm v2/v3 (`packages`) and yarn classic
// / berry (block headers). Anything it cannot read answers null, which the
// caller reports as "declared range" — never as a resolved version.

export interface Installed {
  /** Repo-relative lockfile the versions came from. */
  lockfile: string;
  /** Distinct installed versions, sorted. */
  versions: string[];
}

const READABLE_LOCKFILES = ["pnpm-lock.yaml", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock"] as const;

const toPosix = (p: string) => p.split(sep).join(posix.sep);
const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");

/** `16.3.3(react@19.1.0)` → `16.3.3`; a `link:`/`file:`/`workspace:` spec is not a version. */
function cleanVersion(raw: string): string | undefined {
  const v = raw
    .trim()
    .replace(/^['"]|['"]$/g, "")
    .replace(/\(.*$/, "");
  return /^\d/.test(v) ? v : undefined;
}

function sorted(set: Iterable<string>): string[] {
  return [...new Set(set)].sort();
}

/** The importer block for `importer` (`.` = root), then `pkg`'s `version:` inside it. */
function fromPnpmImporter(lines: string[], importer: string, pkg: string): string | undefined {
  const keyRe = new RegExp(`^ {2}['"]?${escapeRe(importer)}['"]?:\\s*$`);
  const start = lines.findIndex((l) => keyRe.test(l));
  if (start < 0) return undefined;
  const depRe = new RegExp(`^ {6}['"]?${escapeRe(pkg)}['"]?:\\s*$`);
  for (let i = start + 1; i < lines.length; i++) {
    const l = lines[i]!;
    if (/^ {0,2}\S/.test(l)) break; // next importer or top-level section
    if (!depRe.test(l)) continue;
    for (let j = i + 1; j < lines.length && /^ {8}/.test(lines[j]!); j++) {
      const m = /^ {8}version:\s*(.+)$/.exec(lines[j]!);
      if (m) return cleanVersion(m[1]!);
    }
  }
  return undefined;
}

function pnpm(text: string, importer: string, pkg: string): string[] {
  const lines = text.split(/\r?\n/);
  const exact = fromPnpmImporter(lines, importer, pkg);
  if (exact) return [exact];
  // No importer entry (lockfile v5, or a transitive): every installed key.
  const keyRe = new RegExp(`^ {2}['"]?/?${escapeRe(pkg)}[@/](\\d[^(:'"\\s]*)`);
  return sorted(lines.map((l) => keyRe.exec(l)?.[1]).filter((v): v is string => !!v));
}

function npm(text: string, manifestDir: string, pkg: string): string[] {
  let data: { packages?: Record<string, { version?: unknown }>; dependencies?: Record<string, { version?: unknown }> };
  try {
    data = JSON.parse(text);
  } catch {
    return [];
  }
  const pkgs = data.packages ?? {};
  // The workspace's own node_modules first, then the hoisted copy.
  for (const key of [manifestDir ? `${manifestDir}/node_modules/${pkg}` : "", `node_modules/${pkg}`]) {
    const v = key ? pkgs[key]?.version : undefined;
    if (typeof v === "string" && cleanVersion(v)) return [v];
  }
  const legacy = data.dependencies?.[pkg]?.version;
  return typeof legacy === "string" && cleanVersion(legacy) ? [legacy] : [];
}

function yarn(text: string, pkg: string): string[] {
  const out: string[] = [];
  const lines = text.split(/\r?\n/);
  const header = new RegExp(`(?:^|[\\s,"])${escapeRe(pkg)}@`);
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i]!;
    if (/^\s/.test(l) || !l.trim().endsWith(":") || !header.test(l)) continue;
    for (let j = i + 1; j < lines.length && /^\s/.test(lines[j]!); j++) {
      const m = /^\s+version:?\s+"?([^"\s]+)"?/.exec(lines[j]!);
      if (m) {
        const v = cleanVersion(m[1]!);
        if (v) out.push(v);
        break;
      }
    }
  }
  return sorted(out);
}

/**
 * The versions of `pkg` installed for the manifest at `manifestRel`
 * (repo-relative), read from the nearest lockfile at or above it, or null when
 * none records the package.
 */
export function installedVersions(repo: string, manifestRel: string, pkg: string): Installed | null {
  let dir = dirname(join(repo, manifestRel));
  for (;;) {
    for (const name of READABLE_LOCKFILES) {
      const path = join(dir, name);
      if (!existsSync(path)) continue;
      let text: string;
      try {
        text = readFileSync(path, "utf8");
      } catch {
        continue;
      }
      const importer = toPosix(relative(dir, dirname(join(repo, manifestRel)))) || ".";
      const versions =
        name === "pnpm-lock.yaml" ? pnpm(text, importer, pkg) : name === "yarn.lock" ? yarn(text, pkg) : npm(text, importer === "." ? "" : importer, pkg);
      if (versions.length) return { lockfile: toPosix(relative(repo, path)), versions };
    }
    if (relative(repo, dir) === "" || dir === dirname(dir)) return null;
    dir = dirname(dir);
  }
}

/** The range `pkg` is declared with in a package.json, or undefined. */
export function declaredRange(repo: string, manifestRel: string, pkg: string): string | undefined {
  try {
    const m = JSON.parse(readFileSync(join(repo, manifestRel), "utf8")) as Record<string, Record<string, unknown> | undefined>;
    for (const section of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
      const v = m[section]?.[pkg];
      if (typeof v === "string") return v;
    }
  } catch {
    /* unreadable manifest: no range to quote */
  }
  return undefined;
}
