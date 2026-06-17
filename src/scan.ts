import { walkWithMeta, readText } from "./walk.js";
import { langForFile, extract, type Sym, type Imp, type Call } from "./lang.js";
import { byStr, shortHash } from "./util.js";
import type { CacheEntry } from "./cache.js";

export interface FileScan {
  rel: string;
  lang: string;
  symbols: Sym[];
  imports: Imp[];
  calls: Call[];
}

export interface RepoScan {
  repo: string;
  files: FileScan[];
  /** True when the walk hit `--max-files`; some files were not scanned. */
  truncated?: boolean;
  /** Number of files the walk enumerated (pre language-filter). */
  walkedFiles?: number;
}

export interface ScanOptions {
  maxBytes?: number;
  /** Limit the walk to these subdir/glob roots. */
  scope?: string[];
  include?: string[];
  exclude?: string[];
  maxFiles?: number;
  gitignore?: boolean;
}

/** Walk the repo and extract symbols/imports/calls from every recognized file. */
export function scanRepo(repo: string, opts: ScanOptions = {}): RepoScan {
  const { files: walked, truncated } = walkWithMeta(repo, {
    maxBytes: opts.maxBytes,
    scope: opts.scope,
    include: opts.include,
    exclude: opts.exclude,
    maxFiles: opts.maxFiles,
    gitignore: opts.gitignore,
  });
  const files: FileScan[] = [];
  for (const wf of walked) {
    const spec = langForFile(wf.rel);
    if (!spec) continue;
    const { symbols, imports, calls } = extract(spec, readText(wf.abs));
    files.push({ rel: wf.rel, lang: spec.id, symbols, imports, calls });
  }
  files.sort((a, b) => byStr(a.rel, b.rel));
  return { repo, files, truncated, walkedFiles: walked.length };
}

/**
 * Like `scanRepo`, but reuses `cache` for files whose content is unchanged (only
 * re-extracts what moved) and upserts the cache in place. Deterministic: a cache
 * hit yields the identical `FileScan` extraction would produce. Never prunes
 * entries — so it composes with `--scope`/`--diff` (a scoped pass touches a subset
 * but must not evict other scopes' cached work).
 */
export function scanRepoCached(repo: string, opts: ScanOptions, cache: Map<string, CacheEntry>): RepoScan {
  const { files: walked, truncated } = walkWithMeta(repo, {
    maxBytes: opts.maxBytes,
    scope: opts.scope,
    include: opts.include,
    exclude: opts.exclude,
    maxFiles: opts.maxFiles,
    gitignore: opts.gitignore,
  });
  const files: FileScan[] = [];
  for (const wf of walked) {
    const spec = langForFile(wf.rel);
    if (!spec) continue;
    const content = readText(wf.abs);
    const hash = shortHash(content);
    const cached = cache.get(wf.rel);
    let fileScan: FileScan;
    if (cached && cached.hash === hash) {
      fileScan = cached.fileScan; // unchanged — skip the expensive extract()
    } else {
      const { symbols, imports, calls } = extract(spec, content);
      fileScan = { rel: wf.rel, lang: spec.id, symbols, imports, calls };
    }
    files.push(fileScan);
    cache.set(wf.rel, { hash, fileScan });
  }
  files.sort((a, b) => byStr(a.rel, b.rel));
  return { repo, files, truncated, walkedFiles: walked.length };
}
