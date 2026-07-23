import { langForFile, type Sym, type Imp, type Call } from "./lang.js";
import { byStr } from "./util.js";
import type { CacheEntry } from "./cache.js";
import {
  scanRepo as engineScanRepo,
  type FileRecord,
  type RepoScan as EngineRepoScan,
  type ScanOptions as EngineScanOptions,
} from "./vendor/codeindex-engine.mjs";

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
  /** The raw engine scan (richer symbols/refs/calls + doc text). NOT serialized —
   *  a downstream input (e.g. the raw caller-index); never persisted to the dossier. */
  engine?: EngineRepoScan;
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

/** Map ultrasec's scan options onto the engine's. Two mappings are load-bearing:
 *  - `scope: string[]` → engine `include` globs. Each entry must match BOTH the exact
 *    path (a lone file — the `--diff` `src/db.js` case) AND everything beneath it (a
 *    directory), mirroring ultrasec's former `rel === s || rel.startsWith(s + "/")`.
 *    The engine's own single-string `scope` sugar only covers the directory case.
 *  - `gitignore` is coerced to a strict boolean: ultrasec's gitignore is opt-in
 *    (default OFF), but the engine treats `!== false` as ON — passing `undefined`
 *    through would silently start honouring .gitignore. */
function toEngineOptions(opts: ScanOptions): EngineScanOptions {
  const scopeGlobs = (opts.scope ?? []).flatMap((s) => {
    const t = s.replace(/\/+$/, "");
    return [t, `${t}/**`];
  });
  const include = [...(opts.include ?? []), ...scopeGlobs];
  return {
    include: include.length ? include : undefined,
    exclude: opts.exclude,
    maxBytes: opts.maxBytes,
    maxFiles: opts.maxFiles,
    gitignore: opts.gitignore === true,
  };
}

/** Adapt one engine `FileRecord` to ultrasec's `FileScan`, or drop it when its
 *  extension isn't one ultrasec reasons about. `lang` is the ultrasec id (the
 *  catalogs gate on it), NOT the engine's `lang`. */
export function recordToFileScan(f: FileRecord): FileScan | undefined {
  const spec = langForFile(f.rel);
  if (!spec) return undefined;
  return {
    rel: f.rel,
    lang: spec.id,
    symbols: f.symbols.map((s) => ({ name: s.name, kind: s.kind, line: s.line, endLine: s.endLine, exported: s.exported })),
    imports: f.refs.filter((r) => r.kind === "import").map((r) => ({ spec: r.spec })),
    calls: (f.calls ?? []).map((c) => ({ callee: c.name, receiver: c.receiver, line: c.line })),
  };
}

function adapt(repo: string, engine: EngineRepoScan): RepoScan {
  const files: FileScan[] = [];
  for (const f of engine.files) {
    const fs = recordToFileScan(f);
    if (fs) files.push(fs);
  }
  files.sort((a, b) => byStr(a.rel, b.rel));
  return { repo, files, truncated: engine.capped, walkedFiles: engine.files.length, engine };
}

/** Walk the repo and extract symbols/imports/calls from every recognized file. */
export function scanRepo(repo: string, opts: ScanOptions = {}): RepoScan {
  return adapt(repo, engineScanRepo(repo, toEngineOptions(opts)));
}

/**
 * Like `scanRepo`, but reuses `cache` for files whose content is unchanged (the
 * engine skips re-extracting them) and upserts the cache in place. Deterministic:
 * a cache hit yields the identical `FileScan` a fresh scan would produce. Never
 * prunes entries — so it composes with `--scope`/`--diff` (a scoped pass touches a
 * subset but must not evict other scopes' cached work).
 */
export function scanRepoCached(repo: string, opts: ScanOptions, cache: Map<string, CacheEntry>): RepoScan {
  const engine = engineScanRepo(repo, { ...toEngineOptions(opts), cache });
  for (const f of engine.files) cache.set(f.rel, { hash: f.hash, record: f });
  return adapt(repo, engine);
}
