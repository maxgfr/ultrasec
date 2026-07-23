import { execFileSync } from "node:child_process";
import { realpathSync } from "node:fs";
import type { Category } from "../types.js";
import { byStr } from "../util.js";
import { PACKAGE_CHECKER_TAG } from "../vendor/package-checker-script.js";

// The catalog of external OSS scanners ultrasec can orchestrate. ultrasec never
// *requires* any of them — the link-graph + AI taint reasoning is the always-on
// core — but when a scanner is present it is run and its output normalized into
// the unified `Finding` model. This registry is pure data + a presence check,
// so it is trivially testable and the `tools` command is self-contained.

export interface InstallHints {
  brew?: string;
  pip?: string;
  npx?: string;
  go?: string;
  cargo?: string;
  docker?: string;
  /** Node's built-in package-manager shim (pnpm/yarn ship via Corepack, not a
   *  separate install). */
  corepack?: string;
  url?: string;
}

export interface ToolSpec {
  /** Binary name used both as the display id and the detection probe. */
  name: string;
  /** What unified `Finding` category this tool feeds. */
  category: Category;
  /** One-line description. */
  description: string;
  /** Languages / ecosystems it covers ("*" = language-agnostic). */
  languages: string[];
  /** Preferred install routes, best-first. */
  install: InstallHints;
  /** A representative invocation ultrasec uses (documentation only). */
  runHint: string;
  /** Whether ultrasec considers this a primary tool for its category. */
  primary?: boolean;
  /** Display-only presence override for the tool-status listing (e.g. a vendored
   *  script that isn't a PATH binary). Falls back to the PATH probe when absent. */
  detect?: () => { installed: boolean; version?: string };
  /** The actual PATH binary to probe/upgrade when it differs from `name` (e.g.
   *  `npm-audit`'s real binary is `npm`). Falls back to `name` when absent. Used
   *  by `tools --upgrade` (src/commands/tools.ts) — never by `detect()` itself,
   *  which entries with this field override via their own `detect`/`command`. */
  binaryName?: string;
  /** Package identifiers per install manager, when they differ from `name` (e.g.
   *  a Go module path vs. the binary it builds: `golang.org/x/vuln/cmd/govulncheck`).
   *  A manager absent here defaults to `name`. Consumed by `inferOrigin`
   *  (src/tools/origin.ts) to build the exact `tools --upgrade` command —
   *  extends this registry rather than a parallel upgrade-only table. */
  packageIds?: Partial<Record<"brew" | "pipx" | "pip" | "go" | "cargo" | "npm", string>>;
}

export const TOOLS: ToolSpec[] = [
  {
    name: "trivy",
    category: "dep",
    description: "All-in-one scanner: dependency CVEs (SCA), secrets, IaC/misconfig, licenses — across most ecosystems.",
    languages: ["*"],
    install: { brew: "brew install trivy", docker: "aquasec/trivy", url: "https://aquasecurity.github.io/trivy/" },
    runHint: "trivy fs --quiet --format json --scanners vuln,secret,misconfig <repo>",
    primary: true,
  },
  {
    name: "osv-scanner",
    category: "dep",
    description: "Google OSV.dev dependency vulnerability scanner driven by lockfiles.",
    languages: ["*"],
    install: {
      brew: "brew install osv-scanner",
      go: "go install github.com/google/osv-scanner/cmd/osv-scanner@latest",
      url: "https://google.github.io/osv-scanner/",
    },
    runHint: "osv-scanner --format json -r <repo>",
    packageIds: { go: "github.com/google/osv-scanner/cmd/osv-scanner@latest" },
  },
  {
    name: "grype",
    category: "dep",
    description: "Anchore SBOM-based vulnerability scanner (pairs with syft).",
    languages: ["*"],
    install: { brew: "brew install grype", url: "https://github.com/anchore/grype" },
    runHint: "grype dir:<repo> -o json",
  },
  {
    name: "syft",
    category: "dep",
    description: "CycloneDX SBOM generator — dossier deliverable + grype/package-checker input",
    languages: ["*"],
    install: { brew: "brew install syft", url: "https://github.com/anchore/syft" },
    runHint: "syft <repo> -o cyclonedx-json -q",
  },
  {
    name: "opengrep",
    category: "sast",
    description: "Free fork of Semgrep with cross-function taint restored — pattern + dataflow SAST.",
    languages: ["*"],
    install: { url: "https://github.com/opengrep/opengrep", docker: "ghcr.io/opengrep/opengrep" },
    runHint: "opengrep scan --json --config auto <repo>",
    primary: true,
  },
  {
    name: "semgrep",
    category: "sast",
    description: "Pattern + dataflow SAST (cross-file taint is a paid Pro feature).",
    languages: ["*"],
    install: { brew: "brew install semgrep", pip: "pipx install semgrep", url: "https://semgrep.dev/" },
    runHint: "semgrep scan --json --config auto <repo>",
  },
  {
    name: "gitleaks",
    category: "secret",
    description: "Hardcoded-secret detector (git history + working tree).",
    languages: ["*"],
    install: { brew: "brew install gitleaks", url: "https://github.com/gitleaks/gitleaks" },
    runHint: "gitleaks detect --report-format json --no-banner --source <repo>",
    primary: true,
  },
  {
    name: "cargo-audit",
    category: "dep",
    description: "RustSec advisory scanner for Cargo.lock.",
    languages: ["rust"],
    install: { cargo: "cargo install cargo-audit", url: "https://rustsec.org/" },
    runHint: "cargo audit --json",
  },
  {
    name: "govulncheck",
    category: "dep",
    description: "Go vulnerability database scanner (reachability-aware).",
    languages: ["go"],
    install: { go: "go install golang.org/x/vuln/cmd/govulncheck@latest", url: "https://go.dev/security/vuln/" },
    runHint: "govulncheck -json ./...",
    packageIds: { go: "golang.org/x/vuln/cmd/govulncheck@latest" },
  },
  {
    name: "pip-audit",
    category: "dep",
    description: "PyPI advisory scanner for Python requirements/lockfiles.",
    languages: ["python"],
    install: { pip: "pipx install pip-audit", url: "https://pypi.org/project/pip-audit/" },
    runHint: "pip-audit -r requirements.txt -f json",
  },
  {
    name: "npm-audit",
    category: "dep",
    description: "npm's own registry audit of the detected lockfile; needs network (skipped under --offline).",
    languages: ["javascript", "typescript"],
    install: { url: "https://docs.npmjs.com/cli/v10/commands/npm-audit" }, // ships with Node — nothing to install
    runHint: "npm audit --json",
    detect: () => detect("npm"),
    binaryName: "npm",
  },
  {
    name: "pnpm-audit",
    category: "dep",
    description: "pnpm's own registry audit of the detected lockfile; needs network (skipped under --offline).",
    languages: ["javascript", "typescript"],
    install: { corepack: "corepack enable pnpm", url: "https://pnpm.io/cli/audit" },
    runHint: "pnpm audit --json",
    detect: () => detect("pnpm"),
    binaryName: "pnpm",
  },
  {
    name: "yarn-audit",
    category: "dep",
    description: "yarn's own registry audit of the detected lockfile (classic or berry); needs network (skipped under --offline).",
    languages: ["javascript", "typescript"],
    install: { corepack: "corepack enable yarn", url: "https://yarnpkg.com/cli/npm/audit" },
    runHint: "yarn audit --json (classic) / yarn npm audit --json --recursive (berry)",
    detect: () => detect("yarn"),
    binaryName: "yarn",
  },
  {
    name: "package-checker",
    category: "dep",
    description:
      "multi-ecosystem GHSA/OSV lockfile scanner — runs upstream's latest release, vendored sha256-pinned copy as offline/failure fallback (nothing to install)",
    languages: ["*"],
    install: { url: "https://github.com/maxgfr/package-checker.sh" }, // latest by default, vendored + pinned fallback — ships with ultrasec
    runHint: "bash <resolved package-checker.sh> <repo> --default-source-ghsa-osv --export-json <file>",
    // Not a PATH binary — it's resolved (latest, or the vendored fallback) and
    // materialized to the cache dir at runtime (src/tools/package-checker.ts,
    // resolveScriptSource()). "Installed" means the interpreter trio it needs
    // (bash/awk/curl) is present, not any specific script version — the
    // version actually run is decided per-run, not at registry-display time.
    detect: () => {
      const ok = detect("bash").installed && detect("awk").installed && detect("curl").installed;
      return { installed: ok, version: ok ? PACKAGE_CHECKER_TAG : undefined };
    },
  },
  {
    name: "checkov",
    category: "config",
    description: "IaC/misconfig with a cross-resource graph (Terraform, k8s, Dockerfile, CloudFormation…) — deeper than per-block scanning.",
    languages: ["*"],
    install: { pip: "pipx install checkov", docker: "bridgecrew/checkov", url: "https://www.checkov.io/" },
    runHint: "checkov -d <repo> -o json --compact --quiet --soft-fail",
    primary: true,
  },
  {
    name: "bandit",
    category: "sast",
    description: "Python AST security linter — dangerous idioms (shell=True, eval, weak crypto, pickle/yaml.load) a taint engine can't see.",
    languages: ["python"],
    install: { pip: "pipx install bandit", docker: "ghcr.io/pycqa/bandit", url: "https://bandit.readthedocs.io/" },
    runHint: "bandit -r <repo> -f json -ll -ii -q",
  },
  {
    name: "gosec",
    category: "sast",
    description: "Go security checker, stdlib-aware (math/rand, InsecureSkipVerify, exec with tainted args, SQL concat).",
    languages: ["go"],
    install: {
      brew: "brew install gosec",
      go: "go install github.com/securego/gosec/v2/cmd/gosec@latest",
      docker: "ghcr.io/securego/gosec",
      url: "https://github.com/securego/gosec",
    },
    runHint: "gosec -fmt json -quiet -no-fail ./...",
    packageIds: { go: "github.com/securego/gosec/v2/cmd/gosec@latest" },
  },
  {
    name: "hadolint",
    category: "config",
    description: "Dockerfile linter with ShellCheck embedded — audits the bash inside RUN, which trivy/checkov don't.",
    languages: ["docker"],
    install: { brew: "brew install hadolint", docker: "hadolint/hadolint", url: "https://github.com/hadolint/hadolint" },
    runHint: "hadolint --format json --no-fail <Dockerfile…>",
  },
  {
    name: "kingfisher",
    category: "secret",
    description: "Secret scanner: offline checksum+entropy+language-aware pre-filter (fewer FPs), 950+ rules, git history, SARIF.",
    languages: ["*"],
    install: { brew: "brew install kingfisher", docker: "ghcr.io/mongodb/kingfisher", url: "https://github.com/mongodb/kingfisher" },
    runHint: "kingfisher scan <repo> --format sarif --no-validate",
  },
];

export interface ToolStatus extends ToolSpec {
  installed: boolean;
  /** Resolved version string when detectable, else undefined. */
  version?: string;
}

/** `which`/`where` <name> -> its first resolved path, or undefined when it isn't
 *  on PATH. The one place that shells out to which/where — shared by `detect()`'s
 *  existence fallback and `resolveBinaryPath()` below (`tools --upgrade`'s origin
 *  inference, src/tools/origin.ts) so there is exactly one probe to maintain. */
function whichPath(name: string): string | undefined {
  try {
    const out = execFileSync(process.platform === "win32" ? "where" : "which", [name], {
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 5000,
    }).toString();
    return out.split(/\r?\n/)[0]?.trim() || undefined;
  } catch {
    return undefined;
  }
}

/** Probe whether a binary is on PATH (and grab a version line if cheap). */
export function detect(name: string): { installed: boolean; version?: string } {
  try {
    // `--version` is the most portable; fall back to presence-only on failure.
    const out = execFileSync(name, ["--version"], {
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 5000,
    })
      .toString()
      .split("\n")[0]
      ?.trim();
    return { installed: true, version: out || undefined };
  } catch {
    // Some tools (cargo-audit) are subcommands; try a `which`-style probe.
    return { installed: whichPath(name) !== undefined };
  }
}

/**
 * Resolve a binary's real, symlink-resolved absolute path — needed by
 * `tools --upgrade`'s origin inference (src/tools/origin.ts), which reasons
 * about install-manager ownership from the path itself. Symlinks are followed
 * (`realpathSync`) because e.g. pipx shims `~/.local/bin/<tool>` as a symlink
 * into `~/.local/pipx/venvs/<tool>/bin/<tool>` — the shim path alone doesn't
 * contain anything pipx-shaped. Returns undefined when the binary isn't on
 * PATH; falls back to the un-resolved shim path if `realpathSync` itself fails
 * (dangling symlink, permission denied) rather than losing the signal entirely.
 */
export function resolveBinaryPath(name: string): string | undefined {
  const shim = whichPath(name);
  if (!shim) return undefined;
  try {
    return realpathSync(shim);
  } catch {
    return shim;
  }
}

/** The full registry with live presence/version filled in, name-sorted. */
export function toolStatuses(): ToolStatus[] {
  return TOOLS.map((t) => ({ ...t, ...(t.detect?.() ?? detect(t.name)) })).sort((a, b) => byStr(a.name, b.name));
}
