import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Finding } from "../types.js";
import type { ToolAdapter } from "./run.js";
import { makeToolFinding, normalizeSeverity } from "./normalize.js";
import { detect } from "./registry.js";
import { cacheDir } from "./scoring.js";
import { PACKAGE_CHECKER_SH, PACKAGE_CHECKER_SHA256, PACKAGE_CHECKER_TAG } from "../vendor/package-checker-script.js";

// package-checker.sh (https://github.com/maxgfr/package-checker.sh, same author
// as ultrasec) — a single self-contained bash script covering 12 ecosystems
// (npm/yarn/pnpm/bun/deno, PyPI, Go, Cargo, RubyGems, Composer, Maven/Gradle,
// NuGet, Pub, Hex, Swift, GitHub Actions) against GHSA/OSV feeds. It is vendored
// and pinned (src/vendor/package-checker.sh + package-checker.meta.json,
// sha256 drift-gated by scripts/sync-package-checker.mjs --check) and shipped
// embedded as a string in the bundle — see src/vendor/package-checker-script.ts
// — so it survives any packaging path that only copies scripts/ultrasec.mjs.
//
// Network stance: `--default-source-ghsa-osv` resolves feeds via the script's
// find_default_source() (Homebrew share -> ./data/ -> /app/data/ -> a remote
// GitHub raw URL, in that order — see src/vendor/package-checker.sh). There is
// no env var or flag that redirects that search to an arbitrary directory (only
// -s/--source accepts an explicit path/URL, and it is not consulted by the
// default-source resolution); ./data/ is resolved against the RUNNER's cwd,
// which is the scanned repo (see runNative in src/tools/run.ts), not our cache
// dir. So this adapter cannot make the run offline-safe by pointing at a cache
// dir: `network: true` (skipped under --offline). For air-gapped use, warm the
// upstream feeds once and point the script at them explicitly:
//   bash <script> --fetch-all <dir>
//   bash <script> <target> --source <dir>/*.purl --export-json <exportPath>
//
// Feed-poisoning guard: precisely BECAUSE ./data/ is resolved against the
// scanned repo's own cwd (above) and find_default_source() prefers it over
// every other source, a hostile repo can commit its own `data/ghsa.purl` (or
// `data/osv.purl`, or a per-ecosystem `data/{ghsa,osv}-<eco>.purl`) and the
// script will silently treat it as the real advisory feed, suppressing real
// findings or injecting fake ones the AI would then adjudicate as trustworthy.
// `applicable()` below detects any `<repo>/data/*.purl` file — the exact
// shape find_default_source() probes — and skips the adapter with an
// explicit note instead of running against a feed that repo controls.

/** True when `<repo>/data/` contains at least one `*.purl` file — every shape
 *  `find_default_source()` (package-checker.sh) checks under `./data/`
 *  before falling back to Homebrew share / `/app/data` / the real upstream
 *  GitHub feed (`ghsa.purl`, `osv.purl` for npm; `ghsa-<eco>.purl` /
 *  `osv-<eco>.purl` for every other ecosystem). */
function hasRepoLocalPurlFeed(repo: string): boolean {
  let entries: string[];
  try {
    entries = readdirSync(join(repo, "data"));
  } catch {
    return false; // no data/ dir at all — the common, safe case
  }
  return entries.some((e) => e.toLowerCase().endsWith(".purl"));
}

/** Where the vendored script is materialized on disk (content-hash named, so a
 *  version bump writes a fresh file instead of silently reusing a stale one). */
export function scriptPath(): string {
  const dir = join(cacheDir(), "package-checker");
  const path = join(dir, `script-${PACKAGE_CHECKER_SHA256.slice(0, 12)}.sh`);
  if (!existsSync(path)) {
    mkdirSync(dir, { recursive: true });
    writeFileSync(path, PACKAGE_CHECKER_SH);
  }
  return path;
}

// One export file per process (not per run) to avoid two concurrent scans on
// the same host colliding on the same path. Computed lazily and cached in
// module state so it stays stable across the argv()/parse() calls of a run.
let cachedExportPath: string | undefined;
export function exportPath(): string {
  if (!cachedExportPath) cachedExportPath = join(cacheDir(), "package-checker", `export-${process.pid}.json`);
  return cachedExportPath;
}

/** Split "pkg@version" on the LAST "@" (scoped-npm safe: "@scope/name@1.2.3" ->
 *  pkg "@scope/name", version "1.2.3"). No "@" (or a bare "@scope/name" with no
 *  version) keeps the whole string as pkg, version left unset. */
export function splitPkgVersion(raw: string): { pkg: string; version?: string } {
  const at = raw.lastIndexOf("@");
  if (at <= 0) return { pkg: raw };
  return { pkg: raw.slice(0, at), version: raw.slice(at + 1) };
}

/** Map the script's `--export-json` shape into Findings. Exported (rather than
 *  inlined in `parse`) so the mapping is unit-testable without touching disk. */
export function mapExport(data: unknown): Finding[] {
  const vulns = (data as { vulnerabilities?: unknown[] } | null)?.vulnerabilities;
  if (!Array.isArray(vulns)) return [];
  const out: Finding[] = [];
  for (const v of vulns) {
    if (!v || typeof v !== "object") continue;
    const entry = v as Record<string, unknown>;
    const rawPkg = typeof entry.package === "string" ? entry.package : "";
    if (!rawPkg) continue;
    const { pkg, version } = splitPkgVersion(rawPkg);
    const ghsa = typeof entry.ghsa === "string" && entry.ghsa ? entry.ghsa : undefined;
    const cve = typeof entry.cve === "string" && entry.cve ? entry.cve : undefined;
    const ecosystem = typeof entry.ecosystem === "string" && entry.ecosystem ? entry.ecosystem : "unknown";
    const source = typeof entry.source === "string" && entry.source ? entry.source : undefined;
    const file = typeof entry.file === "string" ? entry.file.replace(/^\.\//, "") : undefined;
    const advisory = ghsa ?? cve ?? "advisory";
    const ident = ghsa ?? cve ?? pkg;
    const reference = ghsa ? `https://github.com/advisories/${ghsa}` : cve ? `https://nvd.nist.gov/vuln/detail/${cve}` : undefined;
    out.push(
      makeToolFinding({
        tool: "package-checker",
        category: "dep",
        ident,
        title: `${pkg}: ${advisory}`,
        severity: normalizeSeverity(typeof entry.severity === "string" ? entry.severity : undefined, "medium"),
        message: `${pkg}${version ? `@${version}` : ""}: ${advisory} (${ecosystem}${source ? `, via ${source}` : ""})`,
        file,
        references: reference ? [reference] : [],
        pkg,
        version,
        aliases: [ghsa, cve].filter((x): x is string => Boolean(x)),
      }),
    );
  }
  return out;
}

export const packageChecker: ToolAdapter = {
  name: "package-checker",
  category: "dep",
  network: true,
  applicable: (repo) =>
    hasRepoLocalPurlFeed(repo)
      ? "repo-local data/*.purl would shadow the advisory feeds (feed-poisoning risk) — remove them or scan with trivy/osv-scanner"
      : null,
  command(): string[] | null {
    if (!detect("bash").installed || !detect("awk").installed || !detect("curl").installed) return null;
    // Guard script materialization: cache dir failures (EACCES, ENOSPC, etc.) must
    // not crash the scan. If the script cannot be written, skip gracefully.
    try {
      return ["bash", scriptPath()];
    } catch {
      return null;
    }
  },
  argv(target, ctx): string[] {
    const args = [target, "--default-source-ghsa-osv", "--export-json", exportPath()];
    if (ctx?.sbom) args.push("--source", ctx.sbom);
    return args;
  },
  parse(_raw): Finding[] {
    const path = exportPath();
    let raw: string;
    try {
      raw = readFileSync(path, "utf8");
    } catch {
      return []; // no export file: the run failed before writing it, or found nothing
    }
    try {
      rmSync(path, { force: true });
    } catch {
      /* best-effort cleanup */
    }
    try {
      return mapExport(JSON.parse(raw));
    } catch {
      return []; // malformed export — never throw
    }
  },
};

export { PACKAGE_CHECKER_TAG };
