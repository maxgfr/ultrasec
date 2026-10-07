import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { readText, walk, type RepoTree } from "./walk.js";
import { installedVersions, declaredRange } from "./tools/lockfile-versions.js";
import { compareVersions } from "./deps.js";
import { byStr } from "./util.js";
import { isTestPath } from "./vendor/codeindex-engine.mjs";
import type { Ecosystem } from "./classes/types.js";
import { STACK, ROUTE_EVIDENCE, HTTP_DEPENDENCY, NOT_A_SERVER, ecosystemOfLanguage, type Registry, type StackEntry } from "./stack.js";
import { langForFile } from "./lang.js";
import { findSources } from "./catalog.js";

// Which web frameworks a repository uses, at which version, and where it says
// so — read from the dependency manifests, one package directory at a time.
//
// It exists for the weakness-class packs: a pack is validated against a
// version range (`testedWith`), and a pack applied to a version nobody tested
// is DEGRADED coverage that has to be said out loud and hunted, not trusted.
// That needs the version, and the line that proves it, per package — a
// monorepo's Next.js app and its Express API are two frameworks at two
// versions, not one.
//
// Line-oriented on purpose, like src/tools/lockfile-versions.ts which it
// reuses for npm/pnpm/yarn: no parser may enter the zero-dependency bundle,
// and anything it cannot read is reported without a version rather than with a
// guessed one.

export interface DetectedFramework {
  /** Stack id, as packs name it (`nextjs`, `django`, `net-http`, `next-auth`, …). */
  id: string;
  title: string;
  ecosystem: Ecosystem;
  /**
   * `library` for a library row of the stack table; `inferred` for a web
   * framework the table does not know, inferred from the package's own code
   * (see `inferUnknownFrameworks`). Absent: a known web framework.
   */
  kind?: "library" | "inferred";
  /** Repo-relative package directory (`""` = the repo root). */
  dir: string;
  /** Installed version when a lockfile records it, else the floor of the declared range. */
  version?: string;
  /** Where the version came from. */
  versionSource?: "lockfile" | "declared" | "toolchain";
  /** `file:line` of the declaration. */
  evidence: string;
  /** The languages its code is written in, when not its ecosystem's. */
  languages?: readonly string[];
}

/** The web frameworks of the stack table — what becomes a matrix column. */
export const FRAMEWORKS: readonly StackEntry[] = STACK.filter((e) => e.kind === "web");

export const FRAMEWORK_IDS: readonly string[] = FRAMEWORKS.map((f) => f.id);

/** One dependency declaration read from a manifest. */
interface Declared {
  name: string;
  line: number;
  /** The range/pin as written, when the manifest carries one. */
  spec?: string;
  /** The spec is the toolchain's version (a .NET target framework), not the package's. */
  toolchain?: boolean;
}

const normPy = (n: string): string => n.toLowerCase().replace(/[-_.]+/g, "-");

/** The lowest version a range admits — the honest reading of `^16.2.11` absent a lockfile. */
export function floorOf(spec: string | undefined): string | undefined {
  const m = /(\d+(?:\.\d+){0,3}(?:-[\w.]+)?)/.exec(spec ?? "");
  return m?.[1];
}

/** `1-based line of the first line matching `re`, or 1. */
function lineMatching(lines: string[], re: RegExp): number {
  const i = lines.findIndex((l) => re.test(l));
  return i < 0 ? 1 : i + 1;
}

const esc = (s: string): string => s.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");

// ── Manifest readers ────────────────────────────────────────────────────────

function readPackageJson(text: string): Declared[] {
  let data: Record<string, Record<string, unknown> | undefined>;
  try {
    data = JSON.parse(text);
  } catch {
    return [];
  }
  const lines = text.split(/\r?\n/);
  const out: Declared[] = [];
  for (const section of ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]) {
    for (const [name, spec] of Object.entries(data[section] ?? {})) {
      out.push({
        name: name.toLowerCase(),
        line: lineMatching(lines, new RegExp(`^\\s*"${esc(name)}"\\s*:`)),
        spec: typeof spec === "string" ? spec : undefined,
      });
    }
  }
  return out;
}

function readRequirements(text: string): Declared[] {
  const out: Declared[] = [];
  text.split(/\r?\n/).forEach((raw, i) => {
    const l = raw.replace(/#.*$/, "").trim();
    const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(.*)$/.exec(l);
    if (m && !l.startsWith("-")) out.push({ name: normPy(m[1]!), line: i + 1, spec: m[2]?.trim() || undefined });
  });
  return out;
}

/** PEP 621 `dependencies = ["django>=4.2"]`, Poetry `django = "^4.2"`, Pipfile `django = "==4.2"`. */
function readPyToml(text: string): Declared[] {
  const out: Declared[] = [];
  text.split(/\r?\n/).forEach((raw, i) => {
    const l = raw.replace(/#.*$/, "");
    for (const m of l.matchAll(/["']([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*([<>=!~^][^"';]*)?["']/g))
      out.push({ name: normPy(m[1]!), line: i + 1, spec: m[2]?.trim() });
    const kv = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*(?:["']([^"']*)["']|\{[^}]*version\s*=\s*["']([^"']*)["'])/.exec(l);
    if (kv && !/^(?:name|version|description|python|requires-python|readme|license|build-backend)$/i.test(kv[1]!))
      out.push({ name: normPy(kv[1]!), line: i + 1, spec: kv[2] ?? kv[3] });
  });
  return out;
}

function readPom(text: string): Declared[] {
  const lines = text.split(/\r?\n/);
  const out: Declared[] = [];
  const parent = /<artifactId>\s*spring-boot-starter-parent\s*<\/artifactId>/.test(text)
    ? /<parent>[\s\S]*?<version>\s*([^<\s]+)\s*<\/version>[\s\S]*?<\/parent>/.exec(text)?.[1]
    : undefined;
  const bootProp = /<spring-boot\.version>\s*([^<\s]+)\s*</.exec(text)?.[1];
  lines.forEach((l, i) => {
    const m = /<artifactId>\s*([^<\s]+)\s*<\/artifactId>/.exec(l);
    if (!m) return;
    const own = lines
      .slice(i, i + 4)
      .join("\n")
      .match(/<version>\s*([^<\s$]+)\s*<\/version>/)?.[1];
    out.push({ name: m[1]!.toLowerCase(), line: i + 1, spec: jvmVersion(m[1]!, own, parent ?? bootProp) });
  });
  return out;
}

/**
 * The version a JVM artifact is read at. The `spring` framework is versioned as
 * Spring Boot (what its `testedWith` means): a Boot artifact keeps its own
 * version, a non-Boot `spring-*` artifact's own number is Spring Framework's,
 * so it only inherits the Boot parent/property/plugin. Anything else (Ktor,
 * Quarkus, Jersey) is its own version.
 */
function jvmVersion(artifact: string, own: string | undefined, boot: string | undefined): string | undefined {
  if (artifact.startsWith("spring-boot")) return own ?? boot;
  if (artifact.startsWith("spring-")) return boot;
  return own;
}

function readGradle(text: string, props: Record<string, string> = {}): Declared[] {
  const lines = text.split(/\r?\n/);
  const plugin = /id\s*\(?\s*["']org\.springframework\.boot["']\s*\)?\s*version\s*["']([^"']+)["']/.exec(text)?.[1];
  const out: Declared[] = [];
  lines.forEach((l, i) => {
    for (const m of l.matchAll(/["']([\w.-]+):([\w.-]+)(?::([^"'\s]+))?["']/g)) {
      // `$ktor_version` / `${ktorVersion}`: resolved from gradle.properties when it is there.
      const raw = m[3];
      const own = raw?.startsWith("$") ? props[raw.replace(/^\$\{?|\}$/g, "")] : raw;
      out.push({ name: m[2]!.toLowerCase(), line: i + 1, spec: jvmVersion(m[2]!, own, plugin) });
    }
  });
  return out;
}

function readGoMod(text: string): Declared[] {
  const out: Declared[] = [];
  let inRequire = false;
  text.split(/\r?\n/).forEach((raw, i) => {
    const l = raw.replace(/\/\/.*$/, "").trim();
    if (/^require\s*\($/.test(l)) inRequire = true;
    else if (inRequire && l === ")") inRequire = false;
    const m = (inRequire ? /^(\S+)\s+(v\S+)/ : /^require\s+(\S+)\s+(v\S+)/).exec(l);
    if (m) out.push({ name: m[1]!.toLowerCase(), line: i + 1, spec: m[2]!.replace(/^v/, "") });
  });
  return out;
}

function readGemfile(text: string): Declared[] {
  const out: Declared[] = [];
  text.split(/\r?\n/).forEach((l, i) => {
    const m = /^\s*gem\s+["']([\w-]+)["']\s*(?:,\s*["']([^"']+)["'])?/.exec(l);
    if (m) out.push({ name: m[1]!.toLowerCase(), line: i + 1, spec: m[2] });
  });
  return out;
}

function readComposer(text: string): Declared[] {
  let data: Record<string, Record<string, unknown> | undefined>;
  try {
    data = JSON.parse(text);
  } catch {
    return [];
  }
  const lines = text.split(/\r?\n/);
  const out: Declared[] = [];
  for (const section of ["require", "require-dev"]) {
    for (const [name, spec] of Object.entries(data[section] ?? {})) {
      out.push({
        name: name.toLowerCase(),
        line: lineMatching(lines, new RegExp(`^\\s*"${esc(name)}"\\s*:`)),
        spec: typeof spec === "string" ? spec : undefined,
      });
    }
  }
  return out;
}

/** mix.exs: `{:phoenix, "~> 1.7.14"}`. */
function readMix(text: string): Declared[] {
  const out: Declared[] = [];
  text.split(/\r?\n/).forEach((l, i) => {
    for (const m of l.matchAll(/\{\s*:([a-z0-9_]+)\s*,\s*"([^"]+)"/g)) out.push({ name: m[1]!, line: i + 1, spec: m[2] });
  });
  return out;
}

/** Cargo.toml: `axum = "0.7"` / `axum = { version = "0.7", … }` under a `[*dependencies]` table. */
function readCargo(text: string): Declared[] {
  const out: Declared[] = [];
  let inDeps = false;
  text.split(/\r?\n/).forEach((raw, i) => {
    const l = raw.replace(/#.*$/, "");
    const table = /^\s*\[([^\]]+)\]/.exec(l);
    if (table) {
      inDeps = /(?:^|\.)(?:dev-|build-)?dependencies$/.test(table[1]!.trim());
      return;
    }
    if (!inDeps) return;
    const kv = /^\s*([A-Za-z0-9_-]+)\s*=\s*(?:"([^"]*)"|\{[^}]*?version\s*=\s*"([^"]*)")?/.exec(l);
    if (kv) out.push({ name: kv[1]!.toLowerCase(), line: i + 1, spec: kv[2] ?? kv[3] });
  });
  return out;
}

/** *.csproj: `<PackageReference Include="X" Version="Y" />`, and the project SDK as a dependency. */
function readCsproj(text: string): Declared[] {
  const lines = text.split(/\r?\n/);
  const out: Declared[] = [];
  const target = /<TargetFrameworks?>\s*net(\d+\.\d+)/.exec(text)?.[1];
  lines.forEach((l, i) => {
    const sdk = /<Project\s+Sdk\s*=\s*"([^"]+)"/.exec(l);
    if (sdk) out.push({ name: sdk[1]!.toLowerCase(), line: i + 1, spec: target, toolchain: true });
    for (const m of l.matchAll(/<PackageReference\s+Include\s*=\s*"([^"]+)"(?:\s+Version\s*=\s*"([^"]+)")?/g))
      out.push({ name: m[1]!.toLowerCase(), line: i + 1, spec: m[2] });
  });
  return out;
}

/** deno.json(c) `imports`: `https://deno.land/x/fresh@1.6.8/`, `jsr:@fresh/core@^2`, `npm:hono@4`. */
function readDeno(text: string): Declared[] {
  const lines = text.split(/\r?\n/);
  const out: Declared[] = [];
  lines.forEach((l, i) => {
    for (const m of l.matchAll(/"(?:https?:\/\/deno\.land\/x\/([\w-]+)@([^/"]+)|(?:jsr|npm):(@?[\w.-]+(?:\/[\w.-]+)?)@([^/"]+))/g))
      out.push({ name: (m[1] ?? m[3])!.toLowerCase(), line: i + 1, spec: m[2] ?? m[4] });
  });
  return out;
}

interface ManifestKind {
  registry: Registry;
  match: RegExp;
  read: (text: string, abs: string) => Declared[];
}

/** `key=value` lines of the gradle.properties next to a build file. */
function gradleProps(buildAbs: string): Record<string, string> {
  const text = readIfExists(join(buildAbs, "..", "gradle.properties"));
  const out: Record<string, string> = {};
  for (const m of (text ?? "").matchAll(/^\s*([\w.-]+)\s*=\s*(\S+)\s*$/gm)) out[m[1]!] = m[2]!;
  return out;
}

const MANIFESTS: ManifestKind[] = [
  { registry: "npm", match: /(?:^|\/)package\.json$/, read: readPackageJson },
  { registry: "pypi", match: /(?:^|\/)requirements[\w.-]*\.(?:txt|in)$/, read: readRequirements },
  { registry: "pypi", match: /(?:^|\/)(?:pyproject\.toml|Pipfile|setup\.py)$/, read: readPyToml },
  { registry: "maven", match: /(?:^|\/)pom\.xml$/, read: readPom },
  { registry: "maven", match: /(?:^|\/)build\.gradle(?:\.kts)?$/, read: (text, abs) => readGradle(text, gradleProps(abs)) },
  { registry: "go", match: /(?:^|\/)go\.mod$/, read: readGoMod },
  { registry: "gem", match: /(?:^|\/)Gemfile$/, read: readGemfile },
  { registry: "composer", match: /(?:^|\/)composer\.json$/, read: readComposer },
  { registry: "hex", match: /(?:^|\/)mix\.exs$/, read: readMix },
  { registry: "cargo", match: /(?:^|\/)Cargo\.toml$/, read: readCargo },
  { registry: "nuget", match: /\.csproj$/, read: readCsproj },
  { registry: "deno", match: /(?:^|\/)deno\.jsonc?$/, read: readDeno },
];

// ── Lockfile versions (non-npm) ─────────────────────────────────────────────

function readIfExists(abs: string): string | undefined {
  try {
    return existsSync(abs) ? readFileSync(abs, "utf8") : undefined;
  } catch {
    return undefined;
  }
}

/** poetry.lock / uv.lock: `name = "django"` then `version = "4.2.7"`. Pipfile.lock: JSON. */
function pythonLocked(absDir: string, name: string): string | undefined {
  for (const lock of ["poetry.lock", "uv.lock", "pdm.lock"]) {
    const text = readIfExists(join(absDir, lock));
    if (!text) continue;
    const m = new RegExp(`^name\\s*=\\s*"${esc(name)}"\\s*\\r?\\nversion\\s*=\\s*"([^"]+)"`, "im").exec(text.replace(/_/g, "-"));
    if (m) return m[1];
  }
  const pipfile = readIfExists(join(absDir, "Pipfile.lock"));
  if (pipfile) {
    try {
      const data = JSON.parse(pipfile) as Record<string, Record<string, { version?: string }> | undefined>;
      for (const section of ["default", "develop"]) {
        for (const [k, v] of Object.entries(data[section] ?? {})) if (normPy(k) === name && v.version) return v.version.replace(/^==/, "");
      }
    } catch {
      /* unreadable lockfile: fall back to the declared range */
    }
  }
  return undefined;
}

/** mix.lock: `"phoenix": {:hex, :phoenix, "1.7.14", …}`. */
function hexLocked(absDir: string, name: string): string | undefined {
  const text = readIfExists(join(absDir, "mix.lock"));
  return text ? new RegExp(`"${esc(name)}"\\s*:\\s*\\{\\s*:hex\\s*,\\s*:${esc(name)}\\s*,\\s*"([^"]+)"`).exec(text)?.[1] : undefined;
}

/** Cargo.lock: `name = "axum"` then `version = "0.7.5"`. */
function cargoLocked(absDir: string, name: string): string | undefined {
  const text = readIfExists(join(absDir, "Cargo.lock"));
  return text ? new RegExp(`^name\\s*=\\s*"${esc(name)}"\\s*\\r?\\nversion\\s*=\\s*"([^"]+)"`, "m").exec(text)?.[1] : undefined;
}

function rubyLocked(absDir: string, name: string): string | undefined {
  const text = readIfExists(join(absDir, "Gemfile.lock"));
  return text ? new RegExp(`^ {4}${esc(name)} \\(([^)]+)\\)`, "m").exec(text)?.[1] : undefined;
}

function composerLocked(absDir: string, name: string): string | undefined {
  const text = readIfExists(join(absDir, "composer.lock"));
  if (!text) return undefined;
  try {
    const data = JSON.parse(text) as { packages?: { name?: string; version?: string }[] };
    return data.packages?.find((p) => p.name === name)?.version?.replace(/^v/, "");
  } catch {
    return undefined;
  }
}

function resolveVersion(repo: string, kind: ManifestKind, manifestRel: string, dir: string, d: Declared): Pick<DetectedFramework, "version" | "versionSource"> {
  const absDir = join(repo, dir);
  let locked: string | undefined;
  switch (kind.registry) {
    case "npm": {
      const inst = installedVersions(repo, manifestRel, d.name);
      if (inst?.versions.length) locked = [...inst.versions].sort(compareVersions).at(-1);
      if (!locked) {
        const floor = floorOf(declaredRange(repo, manifestRel, d.name) ?? d.spec);
        return floor ? { version: floor, versionSource: "declared" } : {};
      }
      break;
    }
    case "pypi":
      locked = pythonLocked(absDir, d.name);
      break;
    case "gem":
      locked = rubyLocked(absDir, d.name);
      break;
    case "composer":
      locked = composerLocked(absDir, d.name);
      break;
    case "hex":
      locked = hexLocked(absDir, d.name);
      break;
    case "cargo":
      locked = cargoLocked(absDir, d.name);
      break;
    // go.mod pins an exact minimum version: it is what the build selects.
    case "go":
      locked = d.spec;
      break;
    default:
      break;
  }
  if (locked) return { version: locked, versionSource: "lockfile" };
  const floor = floorOf(d.spec);
  return floor ? { version: floor, versionSource: d.toolchain ? "toolchain" : "declared" } : {};
}

/** Does a declared dependency name match one of an entry's names (`*` = prefix)? */
function nameMatches(declared: string, names: readonly string[]): boolean {
  return names.some((n) => (n.endsWith("*") ? declared.startsWith(n.slice(0, -1)) : declared === n));
}

const dirOf = (rel: string): string => (rel.includes("/") ? rel.slice(0, rel.lastIndexOf("/")) : "");

/**
 * Detect the stack — web frameworks and libraries — of every package in the
 * repository, from the one table in `src/stack.ts`. Deterministic and offline;
 * sorted by package directory then id. `kind` says which rows are libraries.
 */
export function detectFrameworks(repo: string, prune?: (rel: string) => boolean, tree?: RepoTree): DetectedFramework[] {
  const read = tree?.read ?? readText;
  const files = (tree?.files ?? walk(repo)).filter((f) => !prune?.(f.rel));
  const byPackage = new Map<string, DetectedFramework>();
  const add = (f: DetectedFramework) => {
    const key = `${f.dir}\0${f.id}`;
    if (!byPackage.has(key)) byPackage.set(key, f);
  };

  for (const wf of files) {
    const kind = MANIFESTS.find((k) => k.match.test(wf.rel));
    if (!kind) continue;
    const text = read(wf.abs);
    if (!text) continue;
    const dir = dirOf(wf.rel);
    const declared = kind.read(text, wf.abs);
    for (const entry of STACK) {
      const names = entry.deps[kind.registry];
      if (names?.length) {
        const d = declared.find((x) => nameMatches(kind.registry === "pypi" ? normPy(x.name) : x.name, names));
        if (d) add(detected(entry, dir, resolveVersion(repo, kind, wf.rel, dir, d), `${wf.rel}:${d.line}`));
      }

      // A framework with no manifest entry (Go's own server): a package whose
      // code imports it. The version is the toolchain the manifest declares,
      // which is what decides its behaviour.
      if (entry.codeImport?.registry === kind.registry) {
        const prefix = dir ? `${dir}/` : "";
        for (const g of files) {
          if (!g.rel.endsWith(entry.codeImport.extension) || !g.rel.startsWith(prefix) || isTestPath(g.rel)) continue;
          const lines = read(g.abs).split(/\r?\n/);
          const at = lines.findIndex((l) => entry.codeImport!.re.test(l));
          if (at < 0) continue;
          const goLine = /^go\s+(\d+(?:\.\d+)*)/m.exec(text);
          add(detected(entry, dir, goLine ? { version: goLine[1], versionSource: "toolchain" } : {}, `${g.rel}:${at + 1}`));
          break;
        }
      }
    }
  }
  return [...byPackage.values()].sort((a, b) => byStr(a.dir, b.dir) || byStr(a.id, b.id));
}

function detected(entry: StackEntry, dir: string, version: Pick<DetectedFramework, "version" | "versionSource">, evidence: string): DetectedFramework {
  return {
    id: entry.id,
    title: entry.title,
    ecosystem: entry.ecosystem,
    ...(entry.kind === "library" ? { kind: "library" as const } : {}),
    dir,
    ...version,
    evidence,
    ...(entry.languages ? { languages: entry.languages } : {}),
  };
}

/** The web frameworks among a detection — the matrix columns. */
export function webFrameworks(stack: readonly DetectedFramework[]): DetectedFramework[] {
  return stack.filter((f) => f.kind !== "library");
}

/** The context brief's names for a detection, sorted and unique. */
export function stackLabels(stack: readonly DetectedFramework[]): string[] {
  const label = new Map(STACK.map((e) => [e.id, e.label ?? e.id]));
  return [...new Set(stack.map((f) => label.get(f.id) ?? f.id))].sort(byStr);
}

/** The ecosystem a registry's manifests belong to. */
const REGISTRY_ECOSYSTEM: Record<Registry, Ecosystem> = {
  npm: "node",
  pypi: "python",
  maven: "java",
  go: "go",
  gem: "ruby",
  composer: "php",
  hex: "elixir",
  cargo: "rust",
  nuget: "dotnet",
  deno: "deno",
};

/** Lines that are comments in every language the route evidence reads. */
const COMMENT_LINE = /^\s*(?:\/\/|#(?!\[)|\*|\/\*|--)/;

/**
 * Web frameworks the stack table does not know, inferred from a package's own
 * code — see `ROUTE_EVIDENCE` in src/stack.ts for the heuristic and why it is
 * prudent. One `inferred` entry per package (id `unknown`), grounded on its
 * first route declaration. `stack` is what `detectFrameworks` found: a package
 * at or under a known web framework's package is never inferred.
 */
export function inferUnknownFrameworks(
  repo: string,
  stack: readonly DetectedFramework[],
  prune?: (rel: string) => boolean,
  tree?: RepoTree,
): DetectedFramework[] {
  const read = tree?.read ?? readText;
  const files = (tree?.files ?? walk(repo)).filter((f) => !prune?.(f.rel));
  const known = new Set(STACK.flatMap((e) => Object.values(e.deps).flat()));
  const webDirs = stack.filter((f) => f.kind !== "library").map((f) => f.dir);
  const covered = (dir: string): boolean => webDirs.some((w) => w === "" || w === dir || dir.startsWith(`${w}/`));

  // Every package: its manifests' ecosystem, and whether one declares a
  // dependency whose name says it serves HTTP that no table row explains.
  const packages = new Map<string, { ecosystem: Ecosystem; httpDep?: string }>();
  for (const wf of files) {
    const kind = MANIFESTS.find((k) => k.match.test(wf.rel));
    if (!kind) continue;
    const dir = dirOf(wf.rel);
    const pkg = packages.get(dir) ?? { ecosystem: REGISTRY_ECOSYSTEM[kind.registry] };
    if (!pkg.httpDep) {
      const text = read(wf.abs);
      const dep = text
        ? kind
            .read(text, wf.abs)
            .map((d) => d.name)
            .find((n) => HTTP_DEPENDENCY.test(n) && !NOT_A_SERVER.test(n) && !nameMatches(n, [...known]))
        : undefined;
      if (dep) pkg.httpDep = dep;
    }
    packages.set(dir, pkg);
  }
  const dirs = [...packages.keys()].sort((a, b) => b.length - a.length);
  const packageOf = (rel: string): string => dirs.find((d) => d === "" || rel.startsWith(`${d}/`)) ?? "";

  // Evidence lines: route declarations, and the request handlers the walk
  // already knows as HTTP entry points (the catalog's request inputs and route
  // conventions — what `map` and `context` count as the attack surface).
  const evidence = new Map<string, { count: number; at: string; line: number; lang: string }>();
  for (const wf of files) {
    const spec = langForFile(wf.rel);
    if (!spec || isTestPath(wf.rel)) continue;
    const dir = packageOf(wf.rel);
    if (covered(dir)) continue;
    const content = read(wf.abs);
    if (!content) continue;
    const lines = content.split(/\r?\n/);
    const shapes = ROUTE_EVIDENCE[spec.id] ?? [];
    const hits = new Set<number>();
    lines.forEach((l, i) => {
      if (!COMMENT_LINE.test(l) && shapes.some((re) => re.test(l))) hits.add(i + 1);
    });
    for (const h of findSources(spec, content, wf.rel)) if (h.kind === "http" && !COMMENT_LINE.test(lines[h.line - 1] ?? "")) hits.add(h.line);
    if (!hits.size) continue;
    const first = Math.min(...hits);
    const e = evidence.get(dir);
    if (!e) evidence.set(dir, { count: hits.size, at: `${wf.rel}:${first}`, line: first, lang: spec.id });
    else e.count += hits.size;
  }

  const out: DetectedFramework[] = [];
  for (const [dir, e] of evidence) {
    const pkg = packages.get(dir);
    if (e.count < 2 && !pkg?.httpDep) continue;
    out.push({
      id: "unknown",
      title: pkg?.httpDep ? `unknown web framework (\`${pkg.httpDep}\`?)` : "unknown web framework",
      ecosystem: pkg?.ecosystem ?? ecosystemOfLanguage(e.lang) ?? "node",
      kind: "inferred",
      dir,
      evidence: e.at,
      languages: [e.lang],
    });
  }
  return out.sort((a, b) => byStr(a.dir, b.dir));
}

/**
 * Does `version` satisfy `range`? Space-separated comparators (`>=4 <6`), `||`
 * alternatives. Not full semver and it does not need to be: ranges here are
 * written by this repository's own packs.
 */
export function satisfies(version: string, range: string): boolean {
  const v = version.replace(/^v/, "");
  return range.split("||").some((alt) =>
    alt
      .trim()
      .split(/\s+/)
      .filter(Boolean)
      .every((c) => {
        const m = /^(>=|<=|>|<|=)?\s*(.+)$/.exec(c);
        if (!m) return false;
        const cmp = compareVersions(v, m[2]!);
        switch (m[1]) {
          case ">=":
            return cmp >= 0;
          case "<=":
            return cmp <= 0;
          case ">":
            return cmp > 0;
          case "<":
            return cmp < 0;
          default:
            return cmp === 0;
        }
      }),
  );
}
