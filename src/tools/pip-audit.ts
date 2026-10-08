import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Finding } from "../types.js";
import { findManifestDirs } from "../walk.js";
import type { ToolAdapter } from "./run.js";
import { makeToolFinding } from "./normalize.js";

const PY_MANIFESTS = ["requirements.txt", "uv.lock"] as const;

/** The manifest pip-audit audits in `dir`: the uv lockfile only when it stands alone, else requirements.txt. */
function manifestIn(dir: string): (typeof PY_MANIFESTS)[number] {
  return existsSync(join(dir, "uv.lock")) && !existsSync(join(dir, "requirements.txt")) ? "uv.lock" : "requirements.txt";
}

/**
 * pip-audit cannot read `uv.lock` (`--locked` reads PEP 751 `pylock.toml` only), so
 * a uv project is audited through `uv export`: every pinned package of the lock,
 * the project's own workspace members left out (they are not on PyPI). The pins
 * are exact, so `--no-deps --disable-pip` audits them as-is, without pip resolving
 * a second, different environment.
 */
export function exportUvLock(dir: string): { file: string; dispose(): void } | string {
  const tmp = mkdtempSync(join(tmpdir(), "ultrasec-uv-export-"));
  const file = join(tmp, "requirements.txt");
  try {
    execFileSync("uv", ["export", "--frozen", "--no-hashes", "--no-emit-workspace", "--format", "requirements-txt", "-o", file], {
      cwd: dir,
      stdio: ["ignore", "ignore", "pipe"],
      timeout: 120_000,
    });
  } catch (e) {
    rmSync(tmp, { recursive: true, force: true });
    const err = e as NodeJS.ErrnoException & { stderr?: Buffer };
    if (err.code === "ENOENT") return "uv.lock found but `uv` is not installed — it is needed to export the lock for pip-audit";
    return `uv export failed: ${
      String(err.stderr ?? err.message)
        .trim()
        .split("\n")[0]
    }`;
  }
  return { file, dispose: () => rmSync(tmp, { recursive: true, force: true }) };
}

// pip-audit → PyPI/OSV advisory scanner for `requirements.txt` and uv lockfiles,
// at the root or in any workspace below it (`analysis/uv.lock` in a JS monorepo).
// Unlike trivy/osv-scanner (which query a locally-cached vuln DB), it hits PyPI's
// JSON API or OSV.dev on every single invocation — there's no offline mode — so
// it's gated behind `network: true` and skipped under `--offline`.
export const pipAudit: ToolAdapter = {
  name: "pip-audit",
  category: "dep",
  network: true,
  applicable: (repo) => (findManifestDirs(repo, PY_MANIFESTS).length ? null : "no requirements.txt or uv.lock (checked the root and its subdirectories)"),
  workspaces: (repo) => findManifestDirs(repo, PY_MANIFESTS),
  argv: () => ["-r", "requirements.txt", "-f", "json", "--progress-spinner", "off"],
  workspaceArgv(dir, argv) {
    if (manifestIn(dir) === "requirements.txt") return { argv };
    const exported = exportUvLock(dir);
    if (typeof exported === "string") return exported;
    return { argv: ["-r", exported.file, "--no-deps", "--disable-pip", "-f", "json", "--progress-spinner", "off"], dispose: exported.dispose };
  },
  parse(raw, repo, ctx): Finding[] {
    let data: any;
    try {
      data = JSON.parse(raw || "{}");
    } catch {
      return [];
    }
    // Modern pip-audit wraps deps in `{dependencies: [...]}`; tolerate the bare
    // top-level array some older/vendored builds emit.
    const deps: any[] = Array.isArray(data) ? data : Array.isArray(data?.dependencies) ? data.dependencies : [];
    // Cite the manifest of the workspace, repo-relative: the finding id derives from it.
    const ws = ctx?.workspace ?? "";
    const manifest = manifestIn(join(repo, ws));
    const file = ws ? `${ws}/${manifest}` : manifest;
    const out: Finding[] = [];
    for (const dep of deps) {
      const name = dep?.name;
      const version = dep?.version;
      for (const v of (dep?.vulns ?? []).filter(Boolean)) {
        const fixed = (v.fix_versions ?? []).join(", ");
        out.push(
          makeToolFinding({
            tool: "pip-audit",
            category: "dep",
            ident: v.id,
            title: `${name}: ${v.id}`,
            // pip-audit reports no severity at all — default to medium; when this
            // merges with a trivy/osv finding on the same CVE, correlate() takes
            // the MAX severity across sources, so a real (higher) severity wins.
            severity: "medium",
            message: `${name}@${version}: ${v.description || v.id}` + (fixed ? ` (fixed in ${fixed})` : ""),
            file,
            pkg: name,
            version,
            // v.id is usually PYSEC-…/GHSA-…; v.aliases carries the CVE — the join key.
            aliases: [v.id, ...(v.aliases ?? [])],
          }),
        );
      }
    }
    return out;
  },
};
