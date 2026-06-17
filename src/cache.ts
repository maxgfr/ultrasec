import { mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { byStr } from "./util.js";
import type { FileScan } from "./scan.js";

// A content-hash-keyed scan cache under the run dir (`<run>/cache/scan-cache.json`).
// `--resume` reuses the extraction for files whose content is unchanged, so a
// re-audit of a huge repo only re-parses what actually moved. Pure optimization —
// kept OUT of the versioned dossier schema; a `cacheVersion` mismatch invalidates
// the whole cache so a stale format is never trusted.

export const CACHE_VERSION = 1;

export interface CacheEntry {
  /** shortHash of the file's content when it was last extracted. */
  hash: string;
  fileScan: FileScan;
}

interface CacheFile {
  cacheVersion: number;
  entries: Record<string, CacheEntry>;
}

function cachePath(run: string): string {
  return join(run, "cache", "scan-cache.json");
}

/** Load the scan cache (empty map on absence, corruption, or version mismatch). */
export function loadScanCache(run: string): Map<string, CacheEntry> {
  try {
    const data = JSON.parse(readFileSync(cachePath(run), "utf8")) as CacheFile;
    if (!data || data.cacheVersion !== CACHE_VERSION || typeof data.entries !== "object") return new Map();
    return new Map(Object.entries(data.entries));
  } catch {
    return new Map();
  }
}

/** Persist the scan cache deterministically (entries sorted by path). */
export function saveScanCache(run: string, cache: Map<string, CacheEntry>): void {
  const dir = join(run, "cache");
  mkdirSync(dir, { recursive: true });
  const entries: Record<string, CacheEntry> = {};
  for (const [k, v] of [...cache.entries()].sort((a, b) => byStr(a[0], b[0]))) entries[k] = v;
  writeFileSync(cachePath(run), JSON.stringify({ cacheVersion: CACHE_VERSION, entries } satisfies CacheFile, null, 2));
}
