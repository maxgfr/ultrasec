import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { isAbsolute, join, relative } from "node:path";
import type { Finding } from "../types.js";
import type { ToolAdapter } from "./run.js";
import { makeToolFinding, normalizeSeverity } from "./normalize.js";
import { detect, resolveCompatibleBash } from "./registry.js";
import { cacheDir } from "./scoring.js";
import { PACKAGE_CHECKER_SH, PACKAGE_CHECKER_SHA256, PACKAGE_CHECKER_TAG } from "../vendor/package-checker-script.js";
import { declaredRange, installedVersions } from "./lockfile-versions.js";

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

// ── Runtime latest-with-fallback resolution ─────────────────────────────────
//
// By default this adapter tries to run the UPSTREAM latest release of
// package-checker.sh (maxgfr/package-checker.sh — same author as ultrasec, so
// executing its latest release at scan time is first-party trust, not the
// third-party supply-chain hole running arbitrary remote bash would otherwise
// be). The vendored, sha256-pinned copy (src/vendor/package-checker.sh,
// drift-gated by `pnpm run check:build`) stays as the OFFLINE / FAILURE
// fallback: any step below that can fail — DNS, TLS, rate limiting, malformed
// JSON, a full disk — falls straight back to it. `resolveScriptSource` itself
// never throws for a NETWORK reason; it can only propagate if the last-resort
// vendored materialization (`scriptPath()`) itself fails to write to disk —
// `command()` below still wraps it, so that degrades to a graceful skip
// rather than a crash, exactly like the pre-existing vendored-only behavior.
//
//   ULTRASEC_PACKAGE_CHECKER_PINNED=1   force the vendored copy unconditionally,
//                                       skipping network resolution entirely.
//                                       For hardened/offline/air-gapped hosts.
//   ULTRASEC_PACKAGE_CHECKER_API        test-only: override the GitHub API base
//                                       (default https://api.github.com).
//   ULTRASEC_PACKAGE_CHECKER_RAW        test-only: override the raw-content base
//                                       (default https://raw.githubusercontent.com).
//   ULTRASEC_PACKAGE_CHECKER_DEBUG=1    print which script actually ran (tag +
//                                       source) to stderr. `run.ts`'s `finish()`
//                                       builds the per-tool report note generically
//                                       from findings count for every adapter, so
//                                       this is the surface for that detail without
//                                       a runner-contract change for one adapter.
//
// `ToolAdapter.command()` must stay synchronous, so resolution shells out to
// `curl` (already a precondition for this adapter — see the PATH probe below)
// with a short `--max-time` rather than Node's fetch (async-only).
const RESOLVE_CURL_TIMEOUT_S = 4; // curl's own --max-time
const RESOLVE_TIMEOUT_MS = 6_000; // execFileSync hard stop, a beat above curl's
const UPSTREAM_REPO = "maxgfr/package-checker.sh";
/** Conservative allowlist for a resolved tag before it touches a filename or
 *  URL path — closes off a hostile/corrupted API response without needing to
 *  reason about escaping. */
const SAFE_TAG = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

function truthyEnv(v: string | undefined): boolean {
  return v !== undefined && v !== "" && v !== "0" && v.toLowerCase() !== "false";
}

const apiBase = (): string => process.env.ULTRASEC_PACKAGE_CHECKER_API || "https://api.github.com";
const rawBase = (): string => process.env.ULTRASEC_PACKAGE_CHECKER_RAW || "https://raw.githubusercontent.com";

/** `curl` a URL to a Buffer, short-timeout, never throws (null on any failure:
 *  DNS, TLS, non-2xx via `-f`, timeout, curl missing). */
function curlFetch(url: string): Buffer | null {
  try {
    return execFileSync("curl", ["-fsSL", "--max-time", String(RESOLVE_CURL_TIMEOUT_S), url], {
      timeout: RESOLVE_TIMEOUT_MS,
      stdio: ["ignore", "pipe", "ignore"],
    });
  } catch {
    return null;
  }
}

/** GET `{apiBase}/repos/{UPSTREAM_REPO}/releases/latest` -> tag_name, validated
 *  against SAFE_TAG. null on any failure (network, JSON, missing/unsafe field). */
function fetchLatestTag(): string | null {
  const buf = curlFetch(`${apiBase()}/repos/${UPSTREAM_REPO}/releases/latest`);
  if (!buf) return null;
  try {
    const tag = (JSON.parse(buf.toString("utf8")) as { tag_name?: unknown }).tag_name;
    return typeof tag === "string" && SAFE_TAG.test(tag) ? tag : null;
  } catch {
    return null;
  }
}

/** Download `{rawBase}/{UPSTREAM_REPO}/{tag}/script.sh`, cache it content-
 *  addressed under the same cache dir as the vendored script (so a later run
 *  targeting the same tag skips the download), and return its path. null on
 *  any failure (network, empty body, cache-dir write). */
function fetchAndCacheScript(tag: string): string | null {
  const buf = curlFetch(`${rawBase()}/${UPSTREAM_REPO}/${tag}/script.sh`);
  if (!buf?.length) return null;
  const sha12 = createHash("sha256").update(buf).digest("hex").slice(0, 12);
  const dir = join(cacheDir(), "package-checker");
  const path = join(dir, `script-${tag}-${sha12}.sh`);
  try {
    if (!existsSync(path)) {
      mkdirSync(dir, { recursive: true });
      writeFileSync(path, buf);
    }
    return path;
  } catch {
    return null;
  }
}

export interface ScriptSource {
  /** `command()`-shaped executable override: `["bash", <path>]`. */
  cmd: string[];
  /** Human-readable outcome, e.g. "v1.12.0 (latest)" / "v1.11.4 (vendored fallback — <why>)". */
  note: string;
}

/** Decide which package-checker.sh actually runs this scan: upstream latest
 *  (downloaded once per tag, then cached), or the vendored sha256-pinned copy.
 *  Exported for direct unit coverage of the branching. */
export function resolveScriptSource(): ScriptSource {
  if (truthyEnv(process.env.ULTRASEC_PACKAGE_CHECKER_PINNED)) {
    return { cmd: ["bash", scriptPath()], note: `${PACKAGE_CHECKER_TAG} (vendored, pinned)` };
  }
  const tag = fetchLatestTag();
  if (!tag) return { cmd: ["bash", scriptPath()], note: `${PACKAGE_CHECKER_TAG} (vendored fallback — latest-tag lookup failed)` };
  if (tag === PACKAGE_CHECKER_TAG) return { cmd: ["bash", scriptPath()], note: `${PACKAGE_CHECKER_TAG} (vendored, already latest)` };
  const path = fetchAndCacheScript(tag);
  if (!path) return { cmd: ["bash", scriptPath()], note: `${PACKAGE_CHECKER_TAG} (vendored fallback — download of ${tag} failed)` };
  return { cmd: ["bash", path], note: `${tag} (latest)` };
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

const MANIFEST = /(?:^|\/)package\.json$/;

/**
 * A finding cited on a package.json names a version the script read off a
 * RANGE (`"next": "^16.2.11"` → 16.2.11). Replace it with what the lockfile
 * installs, or say it is the declared floor. On a real monorepo the unfixed
 * shape was a critical for next@16.2.11 with only 16.3.3 installed.
 *
 * The advisory itself is not re-evaluated — the export carries no affected
 * range — so a moved version lowers confidence and says what to check.
 */
function resolveManifestVersion(
  repo: string,
  file: string,
  pkg: string,
  version: string,
): { version: string; versionSource?: "lockfile" | "declared-range"; note?: string } {
  if (!MANIFEST.test(file)) return { version };
  // The script reports the path it was handed — absolute on a real run.
  if (isAbsolute(file)) file = relative(repo, file);
  const range = declaredRange(repo, file, pkg);
  const declared = range ? `\`${range}\`` : `a range with floor ${version}`;
  const installed = installedVersions(repo, file, pkg);
  if (!installed) {
    return {
      version,
      versionSource: "declared-range",
      note: `${version} is the declared range floor (${file} declares ${declared}), not an installed version: no lockfile records ${pkg}, so the installed version may differ.`,
    };
  }
  if (installed.versions.includes(version)) return { version };
  if (installed.versions.length === 1) {
    const actual = installed.versions[0]!;
    return {
      version: actual,
      versionSource: "lockfile",
      note: `${file} declares ${declared}; ${installed.lockfile} resolves ${actual}. The advisory was matched against the range floor ${version} — confirm ${actual} is inside its affected range before trusting it.`,
    };
  }
  return {
    version,
    versionSource: "declared-range",
    note: `${version} is the declared range floor (${file} declares ${declared}); ${installed.lockfile} installs ${installed.versions.join(", ")}, none of them ${version}.`,
  };
}

/** Map the script's `--export-json` shape into Findings. Exported (rather than
 *  inlined in `parse`) so the mapping is unit-testable without touching disk.
 *  With `repo`, a finding cited on a package.json names the lockfile-installed
 *  version (see `resolveManifestVersion`). */
export function mapExport(data: unknown, repo?: string): Finding[] {
  const vulns = (data as { vulnerabilities?: unknown[] } | null)?.vulnerabilities;
  if (!Array.isArray(vulns)) return [];
  const out: Finding[] = [];
  for (const v of vulns) {
    if (!v || typeof v !== "object") continue;
    const entry = v as Record<string, unknown>;
    const rawPkg = typeof entry.package === "string" ? entry.package : "";
    if (!rawPkg) continue;
    const split = splitPkgVersion(rawPkg);
    const { pkg } = split;
    const ghsa = typeof entry.ghsa === "string" && entry.ghsa ? entry.ghsa : undefined;
    const cve = typeof entry.cve === "string" && entry.cve ? entry.cve : undefined;
    const ecosystem = typeof entry.ecosystem === "string" && entry.ecosystem ? entry.ecosystem : "unknown";
    const source = typeof entry.source === "string" && entry.source ? entry.source : undefined;
    const file = typeof entry.file === "string" ? entry.file.replace(/^\.\//, "") : undefined;
    const advisory = ghsa ?? cve ?? "advisory";
    const ident = ghsa ?? cve ?? pkg;
    const reference = ghsa ? `https://github.com/advisories/${ghsa}` : cve ? `https://nvd.nist.gov/vuln/detail/${cve}` : undefined;
    const resolved: { version?: string; versionSource?: "lockfile" | "declared-range"; note?: string } =
      repo && file && split.version ? resolveManifestVersion(repo, file, pkg, split.version) : { version: split.version };
    const version = resolved.version;
    const f = makeToolFinding({
      tool: "package-checker",
      category: "dep",
      ident,
      title: `${pkg}: ${advisory}`,
      severity: normalizeSeverity(typeof entry.severity === "string" ? entry.severity : undefined, "medium"),
      message: `${pkg}${version ? `@${version}` : ""}: ${advisory} (${ecosystem}${source ? `, via ${source}` : ""})${resolved.note ? `. ${resolved.note}` : ""}`,
      file,
      references: reference ? [reference] : [],
      pkg,
      version,
      aliases: [ghsa, cve].filter((x): x is string => Boolean(x)),
      ...(resolved.versionSource ? { confidence: "low" as const } : {}),
    });
    if (resolved.versionSource) f.versionSource = resolved.versionSource;
    out.push(f);
  }
  return demotePhantoms(out);
}

/** `pkg@version:advisory` for the hits cited on a lockfile, i.e. on an install. */
const installKey = (f: Finding): string => `${f.pkg}@${f.version}:${f.aliases?.[0] ?? f.title}`;

/**
 * A manifest hit moved to the lockfile-installed version that the script's
 * OWN lockfile pass did not report at that version describes nothing that is
 * installed: the advisory matched a range floor only. It is kept — at info, and
 * saying why — rather than dropped, so the report still shows it was seen. On
 * the real monorepo this was a critical for next@16.2.11 with 16.3.3 installed.
 */
function demotePhantoms(findings: Finding[]): Finding[] {
  const onLockfile = new Set(findings.filter((f) => !f.versionSource && f.sink && !MANIFEST.test(f.sink.file)).map(installKey));
  for (const f of findings) {
    if (f.versionSource !== "lockfile" || onLockfile.has(installKey(f))) continue;
    f.severity = "info";
    f.message += ` package-checker's lockfile pass reported no ${f.aliases?.[0] ?? "advisory"} for ${f.pkg}@${f.version}, so nothing installed is known to be affected — kept at info rather than dropped.`;
  }
  return findings;
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
    const bash = resolveCompatibleBash();
    if (!bash || !detect("awk").installed || !detect("curl").installed) return null;
    // Guard script resolution/materialization end to end: cache dir failures
    // (EACCES, ENOSPC, etc.) must not crash the scan. If nothing can be
    // written, skip gracefully — resolveScriptSource() itself already falls
    // back through every network failure to the vendored copy.
    try {
      const { cmd, note } = resolveScriptSource();
      if (truthyEnv(process.env.ULTRASEC_PACKAGE_CHECKER_DEBUG)) process.stderr.write(`package-checker: ${note}\n`);
      return [bash, ...cmd.slice(1)];
    } catch {
      return null;
    }
  },
  argv(target, ctx): string[] {
    const args = [target, "--default-source-ghsa-osv", "--export-json", exportPath()];
    if (ctx?.sbom) args.push("--source", ctx.sbom);
    return args;
  },
  parse(_raw, repo): Finding[] {
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
      return mapExport(JSON.parse(raw), repo);
    } catch {
      return []; // malformed export — never throw
    }
  },
};

export { PACKAGE_CHECKER_TAG };
