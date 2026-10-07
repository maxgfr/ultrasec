import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { readText, walk, type RepoTree } from "./walk.js";
import { installedVersions, declaredRange } from "./tools/lockfile-versions.js";
import { compareVersions } from "./deps.js";
import { byStr } from "./util.js";
import type { Ecosystem } from "./classes/types.js";

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
  /** Framework id, as packs name it (`nextjs`, `django`, `net-http`, …). */
  id: string;
  title: string;
  ecosystem: Ecosystem;
  /** Repo-relative package directory (`""` = the repo root). */
  dir: string;
  /** Installed version when a lockfile records it, else the floor of the declared range. */
  version?: string;
  /** Where the version came from. */
  versionSource?: "lockfile" | "declared" | "toolchain";
  /** `file:line` of the declaration. */
  evidence: string;
}

interface FrameworkDef {
  id: string;
  title: string;
  ecosystem: Ecosystem;
  /** Dependency names that mean "this package uses the framework" (lower case). */
  packages: string[];
}

/** The frameworks detected. A framework with no pack is still listed: its
 *  classes are then hunted by the AI pass instead of matched by a pack. */
export const FRAMEWORKS: FrameworkDef[] = [
  { id: "nextjs", title: "Next.js", ecosystem: "node", packages: ["next"] },
  { id: "express", title: "Express", ecosystem: "node", packages: ["express"] },
  { id: "nestjs", title: "NestJS", ecosystem: "node", packages: ["@nestjs/core"] },
  { id: "fastify", title: "Fastify", ecosystem: "node", packages: ["fastify"] },
  { id: "koa", title: "Koa", ecosystem: "node", packages: ["koa"] },
  { id: "hono", title: "Hono", ecosystem: "node", packages: ["hono"] },
  { id: "elysia", title: "Elysia", ecosystem: "node", packages: ["elysia"] },
  { id: "nuxt", title: "Nuxt", ecosystem: "node", packages: ["nuxt"] },
  { id: "sveltekit", title: "SvelteKit", ecosystem: "node", packages: ["@sveltejs/kit"] },
  { id: "django", title: "Django", ecosystem: "python", packages: ["django"] },
  { id: "flask", title: "Flask", ecosystem: "python", packages: ["flask"] },
  { id: "fastapi", title: "FastAPI", ecosystem: "python", packages: ["fastapi"] },
  { id: "tornado", title: "Tornado", ecosystem: "python", packages: ["tornado"] },
  { id: "aiohttp", title: "aiohttp", ecosystem: "python", packages: ["aiohttp"] },
  {
    id: "spring",
    title: "Spring Boot",
    ecosystem: "java",
    packages: ["spring-boot-starter-web", "spring-boot-starter-webflux", "spring-webmvc", "spring-webflux"],
  },
  { id: "quarkus", title: "Quarkus", ecosystem: "java", packages: ["quarkus-rest", "quarkus-resteasy", "quarkus-resteasy-reactive"] },
  { id: "micronaut", title: "Micronaut", ecosystem: "java", packages: ["micronaut-http-server-netty"] },
  { id: "gin", title: "Gin", ecosystem: "go", packages: ["github.com/gin-gonic/gin"] },
  { id: "echo", title: "Echo", ecosystem: "go", packages: ["github.com/labstack/echo/v4", "github.com/labstack/echo"] },
  { id: "fiber", title: "Fiber", ecosystem: "go", packages: ["github.com/gofiber/fiber/v2", "github.com/gofiber/fiber/v3"] },
  { id: "chi", title: "chi", ecosystem: "go", packages: ["github.com/go-chi/chi/v5", "github.com/go-chi/chi"] },
  { id: "rails", title: "Ruby on Rails", ecosystem: "ruby", packages: ["rails"] },
  { id: "sinatra", title: "Sinatra", ecosystem: "ruby", packages: ["sinatra"] },
  { id: "laravel", title: "Laravel", ecosystem: "php", packages: ["laravel/framework"] },
  { id: "symfony", title: "Symfony", ecosystem: "php", packages: ["symfony/framework-bundle"] },
  { id: "slim", title: "Slim", ecosystem: "php", packages: ["slim/slim"] },
];

/** Go's standard library server — a framework with no manifest entry, detected
 *  from the `net/http` import of a module's own code. */
const GO_STDLIB: FrameworkDef = { id: "net-http", title: "Go net/http", ecosystem: "go", packages: [] };

export const FRAMEWORK_IDS: readonly string[] = [...FRAMEWORKS.map((f) => f.id), GO_STDLIB.id];

/** One dependency declaration read from a manifest. */
interface Declared {
  name: string;
  line: number;
  /** The range/pin as written, when the manifest carries one. */
  spec?: string;
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
    // The `spring` framework is versioned as Spring Boot (what `testedWith`
    // means): a non-Boot artifact's own version is Spring Framework's, so it
    // only inherits the Boot parent/property, never its own number.
    const boot = m[1]!.startsWith("spring-boot");
    out.push({ name: m[1]!.toLowerCase(), line: i + 1, spec: (boot ? own : undefined) ?? parent ?? bootProp });
  });
  return out;
}

function readGradle(text: string): Declared[] {
  const lines = text.split(/\r?\n/);
  const plugin = /id\s*\(?\s*["']org\.springframework\.boot["']\s*\)?\s*version\s*["']([^"']+)["']/.exec(text)?.[1];
  const out: Declared[] = [];
  lines.forEach((l, i) => {
    for (const m of l.matchAll(/["']([\w.-]+):([\w.-]+)(?::([\w.-]+))?["']/g))
      out.push({ name: m[2]!.toLowerCase(), line: i + 1, spec: (m[2]!.startsWith("spring-boot") ? m[3] : undefined) ?? plugin });
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

interface ManifestKind {
  ecosystem: Ecosystem;
  match: RegExp;
  read: (text: string) => Declared[];
}

const MANIFESTS: ManifestKind[] = [
  { ecosystem: "node", match: /(?:^|\/)package\.json$/, read: readPackageJson },
  { ecosystem: "python", match: /(?:^|\/)requirements[\w.-]*\.(?:txt|in)$/, read: readRequirements },
  { ecosystem: "python", match: /(?:^|\/)(?:pyproject\.toml|Pipfile)$/, read: readPyToml },
  { ecosystem: "java", match: /(?:^|\/)pom\.xml$/, read: readPom },
  { ecosystem: "java", match: /(?:^|\/)build\.gradle(?:\.kts)?$/, read: readGradle },
  { ecosystem: "go", match: /(?:^|\/)go\.mod$/, read: readGoMod },
  { ecosystem: "ruby", match: /(?:^|\/)Gemfile$/, read: readGemfile },
  { ecosystem: "php", match: /(?:^|\/)composer\.json$/, read: readComposer },
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
  if (kind.ecosystem === "node") {
    const inst = installedVersions(repo, manifestRel, d.name);
    if (inst?.versions.length) locked = [...inst.versions].sort(compareVersions).at(-1);
    if (!locked) {
      const range = declaredRange(repo, manifestRel, d.name) ?? d.spec;
      const floor = floorOf(range);
      return floor ? { version: floor, versionSource: "declared" } : {};
    }
  } else if (kind.ecosystem === "python") locked = pythonLocked(absDir, d.name);
  else if (kind.ecosystem === "ruby") locked = rubyLocked(absDir, d.name);
  else if (kind.ecosystem === "php") locked = composerLocked(absDir, d.name);
  // go.mod pins an exact minimum version: it is what the build selects.
  else if (kind.ecosystem === "go" && d.spec) locked = d.spec;
  if (locked) return { version: locked, versionSource: "lockfile" };
  const floor = floorOf(d.spec);
  return floor ? { version: floor, versionSource: "declared" } : {};
}

const dirOf = (rel: string): string => (rel.includes("/") ? rel.slice(0, rel.lastIndexOf("/")) : "");

/**
 * Detect the frameworks of every package in the repository. Deterministic and
 * offline; sorted by package directory then framework id.
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
    const declared = kind.read(text);
    for (const def of FRAMEWORKS) {
      if (def.ecosystem !== kind.ecosystem) continue;
      const d = declared.find((x) => def.packages.includes(kind.ecosystem === "python" ? normPy(x.name) : x.name));
      if (!d) continue;
      add({ id: def.id, title: def.title, ecosystem: def.ecosystem, dir, ...resolveVersion(repo, kind, wf.rel, dir, d), evidence: `${wf.rel}:${d.line}` });
    }

    // Go's own server: a module whose code imports net/http. The version is
    // the toolchain the module declares, which is what decides its behaviour.
    if (kind.ecosystem === "go") {
      const prefix = dir ? `${dir}/` : "";
      for (const g of files) {
        if (!g.rel.endsWith(".go") || !g.rel.startsWith(prefix) || g.rel.endsWith("_test.go")) continue;
        const lines = read(g.abs).split(/\r?\n/);
        const at = lines.findIndex((l) => /^\s*(?:import\s+)?(?:\w+\s+)?"net\/http"\s*$/.test(l));
        if (at < 0) continue;
        const goLine = /^go\s+(\d+(?:\.\d+)*)/m.exec(text);
        add({
          id: GO_STDLIB.id,
          title: GO_STDLIB.title,
          ecosystem: "go",
          dir,
          ...(goLine ? { version: goLine[1], versionSource: "toolchain" as const } : {}),
          evidence: `${g.rel}:${at + 1}`,
        });
        break;
      }
    }
  }
  return [...byPackage.values()].sort((a, b) => byStr(a.dir, b.dir) || byStr(a.id, b.id));
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
