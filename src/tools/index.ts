import type { ToolAdapter } from "./run.js";
import { trivy } from "./trivy.js";
import { gitleaks } from "./gitleaks.js";
import { osvScanner } from "./osv.js";
import { semgrep, opengrep } from "./semgrep.js";
import { cargoAudit } from "./cargo-audit.js";
import { govulncheck } from "./govulncheck.js";

// Every adapter ultrasec knows how to drive. The runner detects which binaries
// are installed and runs only those; the rest are skipped gracefully.
export const ADAPTERS: ToolAdapter[] = [
  trivy,
  opengrep,
  semgrep,
  gitleaks,
  osvScanner,
  cargoAudit,
  govulncheck,
];

export const adapterByName = (name: string): ToolAdapter | undefined => ADAPTERS.find((a) => a.name === name);

export { trivy, gitleaks, osvScanner, semgrep, opengrep, cargoAudit, govulncheck };
export { orchestrate, runAdapter, type ToolAdapter, type ToolRunResult, type OrchestrateResult } from "./run.js";
