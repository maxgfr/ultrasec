import { resolve, join } from "node:path";
import { langForFile, type Sym, type Imp, type Call } from "./lang.js";
import { byStr } from "./util.js";
import type { CacheEntry } from "./cache.js";
import {
  scanRepo as engineScanRepo,
  type FileRecord,
  type RepoScan as EngineRepoScan,
  type ScanOptions as EngineScanOptions,
} from "./vendor/codeindex-engine.mjs";

/** ultrasec's dossier output dir name — mirrors the `--out`/`--run` default used
 *  across every src/commands/*.ts (e.g. `ultrasec scan --out .ultrasec`). The old
 *  src/walk.ts hardcoded this literal into its DEFAULT_IGNORE_DIRS (unconditionally,
 *  by name — not by whatever `--out` a caller actually passed); the adapter mirrors
 *  that same unconditional exclusion below via the engine's `out` self-index guard. */
const DOSSIER_DIRNAME = ".ultrasec";

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

/** Map ultrasec's scan options onto the engine's. Several mappings are load-bearing:
 *  - `scope: string[]` → engine `include` globs. Each entry must match BOTH the exact
 *    path (a lone file — the `--diff` `src/db.js` case) AND everything beneath it (a
 *    directory), mirroring ultrasec's former `rel === s || rel.startsWith(s + "/")`.
 *    The engine's own single-string `scope` sugar only covers the directory case.
 *  - `gitignore` is coerced to a strict boolean: ultrasec's gitignore is opt-in
 *    (default OFF), but the engine treats `!== false` as ON — passing `undefined`
 *    through would silently start honouring .gitignore.
 *  - `maxBytes` defaults to ultrasec's pre-adoption cap, not the engine's own. The old
 *    src/walk.ts fell back to MAX_FILE_BYTES = 1_500_000 when the caller passed none;
 *    the engine's bare default is 1_048_576 (1MB). Passing `opts.maxBytes` through
 *    unmodified would silently shrink the scanned file-set on any real repo carrying
 *    a 1-1.5MB source file (invisible on the golden corpus, which has none) — recall
 *    doctrine: never let an adoption swap narrow what used to be scanned.
 *  - `out` is always the repo's own dossier dir (self-index guard), mirroring the old
 *    walk's unconditional `.ultrasec` entry in DEFAULT_IGNORE_DIRS — see DOSSIER_DIRNAME.
 *
 *  Ignore-dir divergence (accepted, not worked around): the engine's own IGNORE_DIRS
 *  (hardcoded engine-side, not configurable through ScanOptions) additionally skips
 *  .pnpm, bower_components, .svelte-kit, .turbo, .tox, .mypy_cache, .pytest_cache,
 *  .cache, tmp, Pods, DerivedData, .terraform, elm-stuff, .dart_tool — 14 dirs the old
 *  walk didn't know about. Adjudicated class A5: every one is a dependency/build/cache
 *  directory by convention, the same category as ultrasec's own pre-existing exclusions
 *  (node_modules, vendor, dist, build) — never a directory a security audit reasons
 *  about. Accepted as-is; not worth fighting the engine's pruning for. An upstream
 *  engine issue will propose an ignore-override for recall-sensitive consumers like
 *  this one. See the fix commit body for the full adjudication. */
function toEngineOptions(repo: string, opts: ScanOptions): EngineScanOptions {
  const scopeGlobs = (opts.scope ?? []).flatMap((s) => {
    const t = s.replace(/\/+$/, "");
    return [t, `${t}/**`];
  });
  const include = [...(opts.include ?? []), ...scopeGlobs];
  return {
    include: include.length ? include : undefined,
    exclude: opts.exclude,
    maxBytes: opts.maxBytes ?? 1_500_000,
    maxFiles: opts.maxFiles,
    gitignore: opts.gitignore === true,
    out: join(resolve(repo), DOSSIER_DIRNAME),
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
  // NOTE semantic shift vs. pre-adoption: this used to be ultrasec's own walk.ts's
  // enumerated-file count (its own ignore-dirs, its own byte cap). It's now the
  // engine's own walked-file count (pre ultrasec's language filter, like before) —
  // same intent, but produced by a different walk with its own filter surface (see
  // the ignore-dir/byte-cap notes on toEngineOptions above). No reader exists today;
  // flagged so a future one doesn't assume byte-identical semantics with pre-adoption.
  return { repo, files, truncated: engine.capped, walkedFiles: engine.files.length, engine };
}

/** Walk the repo and extract symbols/imports/calls from every recognized file. */
export function scanRepo(repo: string, opts: ScanOptions = {}): RepoScan {
  return adapt(repo, engineScanRepo(repo, toEngineOptions(repo, opts)));
}

/**
 * Like `scanRepo`, but reuses `cache` for files whose content is unchanged (the
 * engine skips re-extracting them) and upserts the cache in place. Deterministic:
 * a cache hit yields the identical `FileScan` a fresh scan would produce. Never
 * prunes entries — so it composes with `--scope`/`--diff` (a scoped pass touches a
 * subset but must not evict other scopes' cached work).
 */
export function scanRepoCached(repo: string, opts: ScanOptions, cache: Map<string, CacheEntry>): RepoScan {
  const engine = engineScanRepo(repo, { ...toEngineOptions(repo, opts), cache });
  for (const f of engine.files) cache.set(f.rel, { hash: f.hash, record: f });
  return adapt(repo, engine);
}
