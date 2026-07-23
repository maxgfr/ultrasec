import { mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { byStr } from "./util.js";
import { EXTRACTOR_VERSION, type FileRecord } from "./vendor/codeindex-engine.mjs";

// A content-hash-keyed scan cache under the run dir (`<run>/cache/scan-cache.json`).
// `--resume` reuses the engine's extraction for files whose content is unchanged, so
// a re-audit of a huge repo only re-parses what actually moved. Pure optimization —
// kept OUT of the versioned dossier schema. Two guards invalidate the whole cache so a
// stale format is never trusted: a `cacheVersion` mismatch (this file's shape changed)
// and an `extractorVersion` mismatch (the vendored engine was re-pinned — its records
// would otherwise be replayed as stale extractions since the cache is keyed by content
// hash alone, which does not change when the extractor does).

export const CACHE_VERSION = 2;

export interface CacheEntry {
  /** Content hash the engine recorded for the file when it was last extracted. */
  hash: string;
  /** The engine's raw extraction record for the file. */
  record: FileRecord;
}

interface CacheFile {
  cacheVersion: number;
  extractorVersion: number;
  entries: Record<string, CacheEntry>;
}

function cachePath(run: string): string {
  return join(run, "cache", "scan-cache.json");
}

/** Load the scan cache (empty map on absence, corruption, or a version/extractor mismatch). */
export function loadScanCache(run: string): Map<string, CacheEntry> {
  try {
    const data = JSON.parse(readFileSync(cachePath(run), "utf8")) as CacheFile;
    if (!data || data.cacheVersion !== CACHE_VERSION || data.extractorVersion !== EXTRACTOR_VERSION || typeof data.entries !== "object") return new Map();
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
  writeFileSync(cachePath(run), JSON.stringify({ cacheVersion: CACHE_VERSION, extractorVersion: EXTRACTOR_VERSION, entries } satisfies CacheFile, null, 2));
}
