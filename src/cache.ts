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

/**
 * Shape check for one cache entry. The cache file lives under the run dir, which
 * is writable by anything that can write the workspace, and `--resume` replays
 * its records straight into the scan without re-reading the source file. A
 * record with the wrong shape (a missing `symbols`, a `lines` that is a string,
 * a `rel` that does not match its key) would surface as a crash — or worse, as a
 * silently wrong link-graph — deep inside the auditors. So every entry is
 * validated against `FileRecord`'s load-bearing fields and a bad one is simply
 * treated as a miss (that file is re-extracted); the rest of the cache still
 * counts.
 */
export function isCacheEntry(key: string, v: unknown): v is CacheEntry {
  if (!v || typeof v !== "object") return false;
  const e = v as { hash?: unknown; record?: unknown };
  if (typeof e.hash !== "string" || e.hash === "") return false;
  if (!e.record || typeof e.record !== "object") return false;
  const r = e.record as Record<string, unknown>;
  if (typeof r.rel !== "string" || typeof r.hash !== "string" || typeof r.lang !== "string" || typeof r.ext !== "string") return false;
  if (typeof r.size !== "number" || typeof r.lines !== "number") return false;
  if (!Array.isArray(r.symbols) || !Array.isArray(r.refs) || !Array.isArray(r.headings)) return false;
  if (r.hash !== e.hash) return false;
  if (r.rel !== key) return false;
  return true;
}

/**
 * Load the scan cache — an empty map on absence, corruption, or a
 * version/extractor mismatch; a partial map when only some entries are
 * malformed (those are dropped, the others kept).
 */
export function loadScanCache(run: string): Map<string, CacheEntry> {
  try {
    const data = JSON.parse(readFileSync(cachePath(run), "utf8")) as CacheFile;
    if (!data || data.cacheVersion !== CACHE_VERSION || data.extractorVersion !== EXTRACTOR_VERSION) return new Map();
    if (!data.entries || typeof data.entries !== "object" || Array.isArray(data.entries)) return new Map();
    const out = new Map<string, CacheEntry>();
    for (const [k, v] of Object.entries(data.entries)) if (isCacheEntry(k, v)) out.set(k, v);
    return out;
  } catch {
    return new Map();
  }
}

// ── Stage timings ────────────────────────────────────────────────────────────
// Wall-clock per stage of a `scan`, written to `<run>/cache/timings.json`.
// Deliberately in the cache dir and nowhere else: `manifest.json` is
// byte-compared between runs and the example audit is committed, and a
// duration in either would make every run a diff.

export interface StageTimer {
  /** Close the running stage (if any) and open `name`. Returns the closed stage. */
  mark(name: string): { name: string; ms: number } | undefined;
  /** Close the running stage and return every stage's duration plus `total`. */
  finish(): Record<string, number>;
}

export function stageTimer(now: () => number = () => performance.now()): StageTimer {
  const timings: Record<string, number> = {};
  const t0 = now();
  let current: string | undefined;
  let started = t0;
  const close = (): { name: string; ms: number } | undefined => {
    if (current === undefined) return undefined;
    const ms = Math.round(now() - started);
    timings[current] = (timings[current] ?? 0) + ms;
    const closed = { name: current, ms };
    current = undefined;
    return closed;
  };
  return {
    mark(name) {
      const closed = close();
      current = name;
      started = now();
      return closed;
    },
    finish() {
      close();
      return { ...timings, total: Math.round(now() - t0) };
    },
  };
}

export function saveTimings(run: string, timings: Record<string, number>): void {
  const dir = join(run, "cache");
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "timings.json"), `${JSON.stringify(timings, null, 2)}\n`);
}

/** Persist the scan cache deterministically (entries sorted by path). */
export function saveScanCache(run: string, cache: Map<string, CacheEntry>): void {
  const dir = join(run, "cache");
  mkdirSync(dir, { recursive: true });
  const entries: Record<string, CacheEntry> = {};
  for (const [k, v] of [...cache.entries()].sort((a, b) => byStr(a[0], b[0]))) entries[k] = v;
  writeFileSync(cachePath(run), JSON.stringify({ cacheVersion: CACHE_VERSION, extractorVersion: EXTRACTOR_VERSION, entries } satisfies CacheFile, null, 2));
}
