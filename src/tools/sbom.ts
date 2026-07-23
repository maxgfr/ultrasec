import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { detect } from "./registry.js";
import { TIMEOUT_MS, MAX_BUFFER } from "./run.js";

// syft (Anchore, pairs with grype) generates a CycloneDX SBOM once per scan — a
// dossier deliverable in its own right, AND faster input for the adapters that
// can consume it instead of re-walking the tree themselves: grype switches to
// `sbom:` mode and package-checker appends it as an extra `--source` (see
// RunContext.sbom in run.ts, and each adapter's own argv()). Absence is the
// NORMAL path — most hosts don't have syft installed — so this producer never
// throws; a scan without it just falls back to each adapter scanning the
// directory directly.

export interface SbomResult {
  /** Absolute path of the written CycloneDX JSON, when syft ran successfully. */
  path?: string;
  /** Human-readable outcome for the scan summary / manifest. */
  note: string;
}

/** Component count from a CycloneDX JSON document — tolerant of any shape;
 *  undefined (rather than 0) when the document can't be parsed, so the note
 *  omits a misleading count instead of claiming zero components. */
function componentCount(cdxJson: string): number | undefined {
  try {
    const data = JSON.parse(cdxJson);
    return Array.isArray(data?.components) ? data.components.length : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Generate `sbom.cdx.json` under `outDir` via `syft`, when installed. Never
 * throws: a missing binary, a failing run, or a write error all collapse into
 * a graceful `{ note }` with no `path` — the caller (scan) treats that as
 * "no SBOM this run" and every consumer already tolerates `ctx.sbom` being
 * unset.
 */
export function generateSbom(repo: string, outDir: string): SbomResult {
  if (!detect("syft").installed) return { note: "syft not installed — no SBOM" };
  try {
    const stdout = execFileSync("syft", [repo, "-o", "cyclonedx-json", "-q"], {
      encoding: "utf8",
      timeout: TIMEOUT_MS,
      maxBuffer: MAX_BUFFER,
      stdio: ["ignore", "pipe", "ignore"],
    });
    mkdirSync(outDir, { recursive: true });
    const path = join(outDir, "sbom.cdx.json");
    writeFileSync(path, stdout);
    const count = componentCount(stdout);
    return { path: resolve(path), note: `sbom.cdx.json${count !== undefined ? ` (${count} components)` : ""}` };
  } catch (e) {
    return { note: `syft failed: ${(e as Error).message}` };
  }
}
