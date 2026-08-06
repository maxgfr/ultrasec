import { existsSync } from "node:fs";
import { join } from "node:path";
import type { Finding } from "../types.js";
import type { ToolAdapter } from "./run.js";
import { makeToolFinding } from "./normalize.js";
import { findManifestDirs } from "../walk.js";

// GuardDog → malicious packages and typosquats.
//
// Every other dep adapter in the belt answers "does this package have a known
// CVE?". That question cannot see the attack that actually happens now: a
// package that was never vulnerable because it was hostile from its first
// publish. An install hook that exfiltrates the environment, a name one keystroke
// from a real one, code fetched at install time from a pastebin — none of it has
// an advisory id, and none of it will, because the class is discovered by
// behaviour rather than by disclosure.
//
// Heuristic by construction, so findings arrive as candidates: a package that
// legitimately compiles a native extension trips the same install-script rule as
// one that phones home.

const MANIFESTS: Record<string, readonly string[]> = {
  npm: ["package.json"],
  pypi: ["requirements.txt", "pyproject.toml", "setup.py"],
  go: ["go.mod"],
  github_action: [".github"],
};

/**
 * Ecosystems this repo actually has, in the priority order the single run uses.
 *
 * GuardDog's CLI takes the ecosystem as its FIRST argument (`guarddog npm verify
 * <path>`), and the adapter contract can only append to argv — `enumerate` puts
 * its values at the end, which would produce `guarddog verify <path> … npm` and
 * fail. So one ecosystem per run, highest-priority first; a polyglot repo needs a
 * second pass with `--tools guarddog` from the other manifest's directory. Said
 * here because a wrong invocation that exits non-zero looks exactly like "tool
 * not installed" in the tool status.
 */
function ecosystems(repo: string): string[] {
  return Object.entries(MANIFESTS)
    .filter(([, names]) => names.some((n) => existsSync(join(repo, n)) || findManifestDirs(repo, [n]).length > 0))
    .map(([eco]) => eco);
}

/** GuardDog reports a confidence-ish `severity`; map conservatively. */
const SEV: Record<string, "critical" | "high" | "medium"> = { critical: "critical", high: "high", medium: "medium" };

export const guarddog: ToolAdapter = {
  name: "guarddog",
  category: "dep",
  // Native-only on purpose. Under docker `target` is /work, which does not exist
  // on the host, so the ecosystem probe below would fall back to npm and audit a
  // Python repo with the wrong ecosystem — a wrong answer is worse than a skip.
  network: true, // fetches the package to inspect what will actually be installed
  applicable: (repo) => (ecosystems(repo).length ? null : "no npm/pypi/go manifest found"),
  argv: (target) => [ecosystems(target)[0] ?? "npm", "verify", target, "--output-format", "json"],
  parse(raw): Finding[] {
    let doc: any;
    try {
      doc = JSON.parse(raw || "{}");
    } catch {
      return [];
    }
    // Either a single result object or an array of them, depending on version.
    const results: any[] = Array.isArray(doc) ? doc : doc.results ? [doc] : [];
    const out: Finding[] = [];
    for (const r of results) {
      const pkg = r.package ?? r.dependency ?? "";
      const version = r.version ?? undefined;
      // `results` maps rule name -> matches (or a message string).
      for (const [rule, detail] of Object.entries(r.results ?? {})) {
        if (!detail || (Array.isArray(detail) && detail.length === 0)) continue;
        const note = typeof detail === "string" ? detail : JSON.stringify(detail).slice(0, 300);
        out.push(
          makeToolFinding({
            tool: "guarddog",
            category: "dep",
            ident: `guarddog:${rule}:${pkg}`,
            title: `Malicious-package heuristic: ${rule} — ${pkg}`,
            severity: SEV[String(r.severity ?? "").toLowerCase()] ?? "high",
            message: `GuardDog matched \`${rule}\` on \`${pkg}\`${version ? `@${version}` : ""}. This is a BEHAVIOURAL heuristic, not an advisory — no CVE exists for a package that was hostile from its first publish. Confirm by reading what the package actually does at install time, then check the name against the one you meant to install.\n\n${note}`,
            pkg: pkg || undefined,
            version,
            cwe: "CWE-506",
            confidence: "low",
          }),
        );
      }
    }
    return out;
  },
};

/** Exported for testing: which manifest files gate which ecosystem. */
export const GUARDDOG_ECOSYSTEMS = MANIFESTS;
