import type { ToolAdapter } from "./run.js";
import { trivy } from "./trivy.js";
import { gitleaks } from "./gitleaks.js";
import { osvScanner } from "./osv.js";
import { semgrep, opengrep } from "./semgrep.js";
import { cargoAudit } from "./cargo-audit.js";
import { govulncheck } from "./govulncheck.js";
import { bandit } from "./bandit.js";
import { gosec } from "./gosec.js";
import { checkov } from "./checkov.js";
import { hadolint } from "./hadolint.js";
import { kingfisher } from "./kingfisher.js";
import { grype } from "./grype.js";
import { pipAudit } from "./pip-audit.js";
import { npmAudit, pnpmAudit, yarnAudit } from "./pm-audit.js";
import { packageChecker } from "./package-checker.js";

// Every adapter ultrasec knows how to drive. The runner detects which binaries
// are installed and runs only those; the rest are skipped gracefully.
export const ADAPTERS: ToolAdapter[] = [
  trivy,
  opengrep,
  semgrep,
  gitleaks,
  osvScanner,
  grype,
  cargoAudit,
  govulncheck,
  pipAudit,
  npmAudit,
  pnpmAudit,
  yarnAudit,
  packageChecker,
  bandit,
  gosec,
  checkov,
  hadolint,
  kingfisher,
];

export const adapterByName = (name: string): ToolAdapter | undefined => ADAPTERS.find((a) => a.name === name);

export {
  trivy,
  gitleaks,
  osvScanner,
  grype,
  semgrep,
  opengrep,
  cargoAudit,
  govulncheck,
  pipAudit,
  npmAudit,
  pnpmAudit,
  yarnAudit,
  packageChecker,
  bandit,
  gosec,
  checkov,
  hadolint,
  kingfisher,
};
export { orchestrate, runAdapter, type ToolAdapter, type ToolRunResult, type OrchestrateResult } from "./run.js";
