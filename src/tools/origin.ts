import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { TOOLS } from "./registry.js";

// `tools --upgrade` needs to know, for an already-INSTALLED native binary,
// which package manager put it there — so it can drive that manager's own
// "upgrade to latest" command rather than ultrasec reinventing a package
// manager. `inferOrigin` answers that from the binary's resolved absolute path
// (see `resolveBinaryPath` in registry.ts) plus the tool's registry entry —
// pure string/path matching, no re-probing of the filesystem beyond the two
// cheap, injectable signals documented on `OriginContext` below.

export type Manager = "brew" | "pipx" | "pip" | "go" | "cargo" | "corepack" | "npm" | "apt" | "unknown";

export interface OriginInfo {
  manager: Manager;
  /** Sequential commands (argv per step) that bring this tool to latest via its
   *  manager. Undefined for `apt` (needs sudo — ultrasec never escalates) and
   *  `unknown` (no manager could be inferred) — callers print a hint instead. */
  upgradeArgv?: string[][];
}

export interface OriginContext {
  /** Real default: `process.platform`. Override to exercise the Linux-only
   *  `apt` branch from any host in tests. */
  platform?: NodeJS.Platform;
  /** Real default: a `dpkg -S <path>` probe (Linux only; never throws — a
   *  missing/failing dpkg just means "not apt-owned"). Override for pure,
   *  offline unit tests instead of relying on the host's actual package DB. */
  aptOwned?: boolean;
  /** Real default: whether a `brew` binary sits alongside the tool in the same
   *  bin dir. Disambiguates the generic `/usr/local/bin` prefix (also used by
   *  manual/FHS installs, especially on Linux) from an actual Homebrew-managed
   *  one; `/opt/homebrew/` and `/usr/local/Cellar/` are unambiguous on their
   *  own and never consult this. Override for pure unit tests. */
  brewPresent?: boolean;
  /** Real default: `os.homedir()`. Backs the `~/go/bin` and `~/.cargo/bin`
   *  checks — injectable so tests never touch the real home directory. */
  home?: string;
  /** Real default: `process.env.GOPATH`. Backs the `$GOPATH/bin` check. */
  gopath?: string;
}

/** True when `path` is `dir` itself or lives under it (segment-boundary safe:
 *  `/a/gob` is NOT under `/a/go`). */
function isUnder(path: string, dir: string): boolean {
  const d = dir.endsWith("/") ? dir.slice(0, -1) : dir;
  return path === d || path.startsWith(`${d}/`);
}

function dpkgOwns(path: string): boolean {
  try {
    execFileSync("dpkg", ["-S", path], { stdio: ["ignore", "ignore", "ignore"], timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

type PkgManager = "brew" | "pipx" | "pip" | "go" | "cargo" | "npm";

/** The package identifier to use for `toolName` under `manager`: the
 *  registry's per-manager override (`ToolSpec.packageIds`) when the tool
 *  declared one — e.g. a Go module path differs completely from the binary it
 *  builds — else the tool name itself (true for every brew/pipx/cargo entry
 *  today: formula/package names match the binary). */
function packageId(toolName: string, manager: PkgManager): string {
  const spec = TOOLS.find((t) => t.name === toolName);
  return spec?.packageIds?.[manager] ?? toolName;
}

/** `go install <module>@<version>` needs an explicit version pin; registry
 *  overrides already carry `@latest` (see govulncheck/gosec/osv-scanner in
 *  registry.ts) but a future go-managed tool without one still gets a safe
 *  default here rather than an invalid bare `go install <module>`. */
function goInstallTarget(toolName: string): string {
  const id = packageId(toolName, "go");
  return id.includes("@") ? id : `${id}@latest`;
}

/**
 * Infer which package manager owns an already-installed native binary from
 * its resolved absolute path (pass the realpath'd path — see
 * `resolveBinaryPath` in registry.ts — so a manager's symlink shim, e.g.
 * pipx's, resolves to its real, manager-shaped target directory), and build
 * the exact command(s) that bring it to latest.
 *
 * Heuristics, checked in order (first match wins) — each documented on its
 * branch below:
 *   1. npm / pnpm / yarn — name-based, always (see the branch for why).
 *   2. Homebrew          — `/opt/homebrew/`, `/usr/local/Cellar/`, or
 *                           `/usr/local/bin/` + a sibling `brew`.
 *   3. pipx               — `.local/pipx` or `pipx/venvs` in the path.
 *   4. Go                 — `$GOPATH/bin` or `~/go/bin`.
 *   5. Cargo               — `~/.cargo/bin`.
 *   6. apt (Linux only)  — dpkg-owned `/usr/bin/*` — print-only, never sudo.
 *   7. else                — unknown; caller prints the registry install hint.
 */
export function inferOrigin(binaryAbsPath: string, toolName: string, ctx: OriginContext = {}): OriginInfo {
  const platform = ctx.platform ?? process.platform;
  const home = ctx.home ?? homedir();

  // 1. npm/pnpm/yarn are Node's own package managers. ultrasec always upgrades
  //    them through themselves rather than whatever put Node on the box:
  //    - npm has no separate Homebrew formula (it ships bundled with the
  //      `node` formula), so a real `brew upgrade npm` doesn't exist —
  //      `npm install -g npm@latest` is the only correct move regardless of
  //      how Node itself was installed.
  //    - pnpm/yarn "ship via Corepack, not a separate install" (this is
  //      already this registry's own documented stance — see
  //      InstallHints.corepack) — so they're treated as corepack-managed even
  //      when a `brew install pnpm` formula also exists; this is a deliberate
  //      simplification, not a path-derived fact.
  if (toolName === "npm") return { manager: "npm", upgradeArgv: [["npm", "install", "-g", "npm@latest"]] };
  if (toolName === "pnpm" || toolName === "yarn" || binaryAbsPath.includes("/corepack/")) {
    return { manager: "corepack", upgradeArgv: [["corepack", "up"]] };
  }

  // 2. Homebrew. `/opt/homebrew/` (Apple Silicon's default prefix) and
  //    `/usr/local/Cellar/` (Homebrew's own store dir, any platform) are
  //    unambiguous on their own — nothing else installs there. Bare
  //    `/usr/local/bin/` is ALSO Homebrew's real bin dir on Intel macOS, but
  //    on Linux it's the generic FHS "locally installed software" dir (manual
  //    installs, `pip install --user`, …) — so it only counts brew when a
  //    `brew` binary actually sits alongside it (cheap sibling check, no
  //    subprocess / PATH search).
  if (binaryAbsPath.includes("/opt/homebrew/") || binaryAbsPath.includes("/usr/local/Cellar/")) {
    return { manager: "brew", upgradeArgv: [["brew", "upgrade", packageId(toolName, "brew")]] };
  }
  if (binaryAbsPath.includes("/usr/local/bin/")) {
    const brewPresent = ctx.brewPresent ?? existsSync(join(dirname(binaryAbsPath), "brew"));
    if (brewPresent) return { manager: "brew", upgradeArgv: [["brew", "upgrade", packageId(toolName, "brew")]] };
  }

  // 3. pipx: dedicated per-package venvs under `~/.local/pipx/venvs/<pkg>/…`
  //    (or `~/.local/share/pipx/venvs/<pkg>/…` on older pipx). `which` alone
  //    would return the `~/.local/bin` shim, which doesn't match either
  //    pattern — callers must pass the realpath'd target (see docstring).
  if (binaryAbsPath.includes(".local/pipx") || binaryAbsPath.includes("pipx/venvs")) {
    return { manager: "pipx", upgradeArgv: [["pipx", "upgrade", packageId(toolName, "pipx")]] };
  }

  // 4. Go: `$GOPATH/bin` when GOPATH is set, else the default `~/go/bin`.
  const gopath = ctx.gopath ?? process.env.GOPATH;
  if ((gopath && isUnder(binaryAbsPath, join(gopath, "bin"))) || isUnder(binaryAbsPath, join(home, "go", "bin"))) {
    return { manager: "go", upgradeArgv: [["go", "install", goInstallTarget(toolName)]] };
  }

  // 5. Cargo: `~/.cargo/bin`. `--force` because `cargo install` refuses a
  //    no-op reinstall of an already-installed version — without it a crate
  //    that's already current would silently do nothing on every run.
  if (isUnder(binaryAbsPath, join(home, ".cargo", "bin"))) {
    return { manager: "cargo", upgradeArgv: [["cargo", "install", packageId(toolName, "cargo"), "--force"]] };
  }

  // 6. apt (Linux only): a dpkg-owned `/usr/bin/*` binary. Print-only —
  //    upgrading it needs `apt upgrade`, which needs sudo; ultrasec NEVER
  //    escalates privileges, so no upgradeArgv is ever returned here.
  if (platform === "linux" && binaryAbsPath.startsWith("/usr/bin/")) {
    const owned = ctx.aptOwned ?? dpkgOwns(binaryAbsPath);
    if (owned) return { manager: "apt" };
  }

  // 7. Nothing matched — unknown origin. Caller falls back to the registry's
  //    own install hint (brew/pip/go/cargo/docker/url) instead of a command.
  return { manager: "unknown" };
}
