import { execFileSync } from "node:child_process";
import { flagBool, println, type ParsedArgs } from "../util.js";
import { toolStatuses, detect, resolveBinaryPath, type ToolStatus } from "../tools/registry.js";
import { inferOrigin, type Manager } from "../tools/origin.js";
import { TIMEOUT_MS, MAX_BUFFER } from "../tools/run.js";

// `ultrasec tools` — show the external scanner catalog with live presence and
// install hints. ultrasec degrades gracefully: it runs whatever is installed and
// tells you how to get the rest. The graph + AI taint reasoning always work.
//
// `ultrasec tools --upgrade [--dry-run]` completes the "latest-first everywhere"
// story for NATIVE binaries: docker-mode scanners already track `:latest` with
// `--pull always` (src/tools/run.ts), package-checker already resolves
// upstream's latest release at scan time (src/tools/package-checker.ts) — this
// is the third leg, driving each installed native tool's own package manager
// (inferred by `inferOrigin`, src/tools/origin.ts) to its latest version.

function bestInstallHint(t: ToolStatus): string {
  const i = t.install;
  return i.brew ?? i.pip ?? i.go ?? i.cargo ?? i.npx ?? i.corepack ?? i.docker ?? i.url ?? "";
}

export function runTools(args: ParsedArgs): number {
  const statuses = toolStatuses();

  if (flagBool(args, "upgrade")) return runUpgrade(statuses, flagBool(args, "dry-run"));

  if (flagBool(args, "json")) {
    println(JSON.stringify(statuses, null, 2));
    return 0;
  }

  const installed = statuses.filter((t) => t.installed);
  const missing = statuses.filter((t) => !t.installed);

  println(`ultrasec external scanners — ${installed.length}/${statuses.length} installed\n`);

  const row = (t: ToolStatus): string => {
    const mark = t.installed ? "✓" : "·";
    const star = t.primary ? "*" : " ";
    const ver = t.version ? `  (${t.version})` : "";
    return `  ${mark}${star} ${t.name.padEnd(14)} ${t.category.padEnd(7)} ${t.description}${ver}`;
  };

  if (installed.length) {
    println("INSTALLED");
    for (const t of installed) println(row(t));
    println("");
  }

  println("AVAILABLE TO INSTALL");
  for (const t of missing) {
    println(row(t));
    const hint = bestInstallHint(t);
    if (hint) println(`        → ${hint}`);
  }

  println("\n  * = primary tool for its category. ✓ = on PATH.");
  println("  ultrasec runs the installed tools and normalizes their output; none are required.");
  return 0;
}

// ── `tools --upgrade` ────────────────────────────────────────────────────────

const SELF_UPDATING_NOTE = "self-updating at scan time (latest release + vendored fallback)";
const DOCKER_NOTE = "docker-mode scans already refresh themselves (--pull always) — nothing to upgrade there.";

/** What `--upgrade` decided to do (or not do) for one installed tool, before
 *  anything is actually run. Building this is pure (no execFileSync) so
 *  `--dry-run` and the real run share one plan and can never disagree. */
interface UpgradePlan {
  /** Display id, as shown by the default listing (e.g. "npm-audit"). */
  name: string;
  /** The binary actually probed/upgraded — differs from `name` for the
   *  package-manager audits (npm-audit's real binary is `npm`). */
  probeName: string;
  manager: Manager | "n/a";
  before?: string;
  /** Present ⇒ actionable: the exact commands to run. Absent ⇒ skip, with
   *  `skipDetail` explaining why (unknown origin, apt/sudo, self-updating). */
  argv?: string[][];
  skipDetail?: string;
}

function planUpgrade(t: ToolStatus): UpgradePlan {
  if (t.name === "package-checker") {
    return { name: t.name, probeName: t.name, manager: "n/a", skipDetail: SELF_UPDATING_NOTE };
  }
  const probeName = t.binaryName ?? t.name;
  const before = t.version;
  const path = resolveBinaryPath(probeName);
  if (!path) {
    return { name: t.name, probeName, manager: "unknown", before, skipDetail: bestInstallHint(t) || "no install hint on file" };
  }
  const origin = inferOrigin(path, probeName);
  if (origin.manager === "apt") {
    return {
      name: t.name,
      probeName,
      manager: "apt",
      before,
      skipDetail: `system package (apt) — needs sudo, ultrasec never escalates; upgrade it yourself: sudo apt install --only-upgrade ${probeName}`,
    };
  }
  if (!origin.upgradeArgv?.length) {
    return { name: t.name, probeName, manager: origin.manager, before, skipDetail: bestInstallHint(t) || "no install hint on file" };
  }
  return { name: t.name, probeName, manager: origin.manager, before, argv: origin.upgradeArgv };
}

/** Print, per plan, the exact command(s) `--upgrade` would run — nothing is
 *  executed. Exported for direct unit coverage of the rendering. */
function fmtArgv(argv: string[][]): string {
  return argv.map((cmd) => cmd.join(" ")).join(" && ");
}

function renderDryRun(plans: UpgradePlan[]): void {
  println(`ultrasec tools --upgrade --dry-run — ${plans.length} installed tool(s), nothing will run\n`);
  for (const p of plans) {
    const label = `  ${p.name.padEnd(14)} [${p.manager}]`;
    if (p.argv) println(`${label}  would run: ${fmtArgv(p.argv)}`);
    else println(`${label}  ${p.skipDetail}`);
  }
  println(`\n  ${DOCKER_NOTE}`);
}

/**
 * Run one upgrade step's argv via `execFileSync`, with the same timeout/buffer
 * discipline as every other subprocess ultrasec spawns (src/tools/run.ts).
 * Exported for direct unit coverage of the real-execution path — with a fake
 * command (never a real package manager) so the test suite never actually
 * upgrades anything. NEVER throws: any failure (non-zero exit, missing binary,
 * timeout) comes back as `{ ok: false }`, so one tool's failure can never abort
 * the rest of the run.
 */
export function runUpgradeCommand(argv: string[][]): { ok: boolean; detail: string } {
  for (const cmd of argv) {
    const [bin, ...rest] = cmd;
    if (!bin) continue;
    try {
      execFileSync(bin, rest, { timeout: TIMEOUT_MS, maxBuffer: MAX_BUFFER, stdio: ["ignore", "ignore", "pipe"] });
    } catch (e) {
      const err = e as { stderr?: Buffer | string; message?: string };
      const stderrTail = err.stderr?.toString().trim().split("\n").filter(Boolean).slice(-1)[0];
      return { ok: false, detail: stderrTail || err.message || "upgrade command failed" };
    }
  }
  return { ok: true, detail: "" };
}

function executeUpgrade(plans: UpgradePlan[]): void {
  println(`ultrasec tools --upgrade — ${plans.length} installed tool(s)\n`);
  for (const p of plans) {
    const label = `  ${p.name.padEnd(14)} [${p.manager}]`;
    if (!p.argv) {
      println(`${label}  skipped-unknown-origin — ${p.skipDetail}`);
      continue;
    }
    const { ok, detail } = runUpgradeCommand(p.argv);
    if (!ok) {
      println(`${label}  failed — ${detail}`);
      continue;
    }
    const after = detect(p.probeName).version;
    if (p.before && after && p.before !== after) println(`${label}  upgraded — ${p.before} → ${after}`);
    else println(`${label}  already-latest${after ? ` (${after})` : ""}`);
  }
  println(`\n  ${DOCKER_NOTE}`);
}

/** `--upgrade` never fails the command itself — every per-tool outcome
 *  (upgraded/already-latest/failed/skipped-unknown-origin) is recorded in the
 *  printed table, never fatal. A non-zero exit is reserved for the flag
 *  itself being misused, which doesn't currently apply to this flag. */
function runUpgrade(statuses: ToolStatus[], dryRun: boolean): number {
  const plans = statuses.filter((t) => t.installed).map(planUpgrade);
  if (dryRun) renderDryRun(plans);
  else executeUpgrade(plans);
  return 0;
}
