import { execFileSync } from "node:child_process";
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
  },
  {
    name: "pnpm-audit",
    category: "dep",
    description: "pnpm's own registry audit of the detected lockfile; needs network (skipped under --offline).",
    languages: ["javascript", "typescript"],
    install: { corepack: "corepack enable pnpm", url: "https://pnpm.io/cli/audit" },
    runHint: "pnpm audit --json",
    detect: () => detect("pnpm"),
  },
  {
    name: "yarn-audit",
    category: "dep",
    description: "yarn's own registry audit of the detected lockfile (classic or berry); needs network (skipped under --offline).",
    languages: ["javascript", "typescript"],
    install: { corepack: "corepack enable yarn", url: "https://yarnpkg.com/cli/npm/audit" },
    runHint: "yarn audit --json (classic) / yarn npm audit --json --recursive (berry)",
    detect: () => detect("yarn"),
  },
  {
    name: "package-checker",
    category: "dep",
    description: "vendored multi-ecosystem GHSA/OSV lockfile scanner (nothing to install)",
    languages: ["*"],
    install: { url: "https://github.com/maxgfr/package-checker.sh" }, // vendored + pinned — ships with ultrasec
    runHint: "bash <vendored package-checker.sh> <repo> --default-source-ghsa-osv --export-json <file>",
    // Not a PATH binary — it's vendored bash, materialized to the cache dir at
    // runtime (src/tools/package-checker.ts). "Installed" means the interpreter
    // trio it needs (bash/awk/curl) is present, not the script itself.
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
    try {
      execFileSync(process.platform === "win32" ? "where" : "which", [name], {
        stdio: ["ignore", "ignore", "ignore"],
        timeout: 5000,
      });
      return { installed: true };
    } catch {
      return { installed: false };
    }
  }
}

/** The full registry with live presence/version filled in, name-sorted. */
export function toolStatuses(): ToolStatus[] {
  return TOOLS.map((t) => ({ ...t, ...(t.detect?.() ?? detect(t.name)) })).sort((a, b) => byStr(a.name, b.name));
}
