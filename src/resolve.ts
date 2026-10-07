// Import resolution, delegated to the vendored codeindex engine
// (buildResolveContext + resolveImport). The engine's resolver is a strict
// superset of ultrasec's former heuristic: relative/dotted paths, extension and
// index/package guessing PLUS tsconfig/jsconfig path aliases, package.json
// `exports`, go.mod/replace, Cargo crates, Java/C#/PHP-PSR4 roots. On ultrasec's
// own fixtures it resolves import-for-import identically to the old resolver
// (verified differentially before adoption); on real repos it resolves strictly
// more edges (documented as an accepted, more-correct divergence).
import type { RepoScan } from "./scan.js";
import { walk, type WalkedFile } from "./walk.js";
import { buildResolveContext, resolveImport as engineResolveImport, type ResolveContext } from "./vendor/codeindex-engine.mjs";

function extOf(rel: string): string {
  const i = rel.lastIndexOf(".");
  return i < 0 ? "" : rel.slice(i).toLowerCase();
}

// Manifest basenames buildResolveContext discovers FROM THE FILE LIST (its
// content it then reads from disk): tsconfig/jsconfig path aliases, package
// exports/workspaces, go.mod, Cargo crates, composer PSR-4, python roots.
// ultrasec's scan keeps code files only, so these must be surfaced explicitly —
// without them the engine context is empty and alias resolution is inert.
const MANIFEST_BASES = new Set(["tsconfig.json", "jsconfig.json", "package.json", "go.mod", "cargo.toml", "composer.json", "pyproject.toml", "setup.py"]);

/** Adapt ultrasec's RepoScan to the minimal engine scan shape buildResolveContext
 *  consumes: per file `rel`/`ext` (+`pkg` for Java/C# roots), with the repo's
 *  manifest files APPENDED so the engine can discover tsconfig paths, package
 *  exports, go/cargo/composer roots (their content is read from disk via
 *  `root`). Manifests are collected by an unscoped walk on purpose: a root
 *  tsconfig must configure alias resolution even when the scan is scoped to a
 *  subdirectory. Cast through the engine's expected type — the extra FileRecord
 *  fields are never touched. */
function engineScan(scan: RepoScan, tree?: readonly WalkedFile[]): Parameters<typeof buildResolveContext>[0] {
  const files: { rel: string; ext: string }[] = scan.files.map((f) => ({ rel: f.rel, ext: extOf(f.rel) }));
  const seen = new Set(scan.files.map((f) => f.rel));
  for (const f of tree ?? walk(scan.repo)) {
    const base = f.rel.slice(f.rel.lastIndexOf("/") + 1).toLowerCase();
    if (!MANIFEST_BASES.has(base) || seen.has(f.rel)) continue;
    seen.add(f.rel);
    files.push({ rel: f.rel, ext: extOf(f.rel) });
  }
  return { root: scan.repo, files } as unknown as Parameters<typeof buildResolveContext>[0];
}

/**
 * Files the resolve context had to leave out, and why. A context the vendored
 * engine cannot build is not a reason to lose the whole scan: on a Phoenix repo
 * its Elixir module index read `symbols` off every `.ex` record this adapter
 * hands it — records that carry only `rel`/`ext` — and the TypeError took the
 * scan down before a single finding was written. The guard below keeps the
 * scan, drops the extension whose records the engine choked on, and says so in
 * the manifest: imports INTO those files are not resolved, which is degraded
 * coverage a reader has to be told about, not a silent gap.
 */
export interface ResolutionGap {
  /** File extension left out of the resolve context (`.ex`), or `*` when nothing could be kept. */
  ext: string;
  /** How many files that was. */
  files: number;
  /** The engine's error, as thrown. */
  reason: string;
}

/** Build the engine's resolve context, leaving out the one extension it cannot
 *  build from rather than failing — and recording what was left out. */
function guardedContext(scan: RepoScan, tree: readonly WalkedFile[] | undefined, gaps: ResolutionGap[]): ResolveContext {
  const es = engineScan(scan, tree);
  let reason: string;
  try {
    return buildResolveContext(es);
  } catch (e) {
    reason = e instanceof Error ? e.message : String(e);
  }
  const files = es.files as { rel: string; ext: string }[];
  // Find the extensions the engine cannot index on their own, leave them all
  // out, and build from the rest.
  const bad = [...new Set(files.map((f) => f.ext))].sort().filter((ext) => {
    try {
      buildResolveContext({ ...es, files: files.filter((f) => f.ext === ext) } as typeof es);
      return false;
    } catch {
      return true;
    }
  });
  if (bad.length) {
    const kept = files.filter((f) => !bad.includes(f.ext));
    try {
      const ctx = buildResolveContext({ ...es, files: kept } as typeof es);
      for (const ext of bad) gaps.push({ ext: ext || "(none)", files: files.filter((f) => f.ext === ext).length, reason });
      return ctx;
    } catch {
      /* the failure is in how the groups combine — fall through to the bare file set */
    }
  }
  gaps.push({ ext: "*", files: files.length, reason });
  return ctxFromFileSet(new Set(files.map((f) => f.rel)));
}

/** A repo-file import resolver bound to a scan's full resolve context (tsconfig
 *  paths, workspace exports, module roots). Returns the resolved repo-relative
 *  target, or undefined for external/dangling specifiers. `gaps` collects what
 *  the context had to leave out (see `ResolutionGap`). */
export function buildFileResolver(
  scan: RepoScan,
  tree?: readonly WalkedFile[],
  gaps: ResolutionGap[] = [],
): (fromRel: string, spec: string) => string | undefined {
  const ctx = guardedContext(scan, tree, gaps);
  return (fromRel, spec) => {
    const r = engineResolveImport(fromRel, extOf(fromRel), spec, ctx);
    return r.kind === "resolved" && r.target !== fromRel ? r.target : undefined;
  };
}

/** Build a minimal resolve context from a bare file set (no on-disk manifests) —
 *  the path/index/extension-guessing core of the engine resolver. */
function ctxFromFileSet(fileSet: Set<string>): ResolveContext {
  const filesByDir = new Map<string, string[]>();
  const dirSet = new Set<string>();
  for (const rel of fileSet) {
    const slash = rel.lastIndexOf("/");
    const dir = slash < 0 ? "" : rel.slice(0, slash);
    let list = filesByDir.get(dir);
    if (!list) filesByDir.set(dir, (list = []));
    list.push(rel);
    let d = dir;
    while (d) {
      if (dirSet.has(d)) break;
      dirSet.add(d);
      const s = d.lastIndexOf("/");
      d = s < 0 ? "" : d.slice(0, s);
    }
  }
  return {
    fileSet,
    dirSet,
    filesByDir,
    tsConfigs: [],
    goModules: [],
    rustCrates: [],
    javaRoots: [],
    pyRoots: [""],
    workspacePackages: [],
    packageScopes: [],
    cIncludeRoots: [],
    rubyLibRoots: [],
    phpPsr4: [],
    csharpNamespaces: new Map(),
    warnings: [],
  };
}

/** Back-compat single-call resolver: resolve `spec` from `fromRel` against a bare
 *  file set. Retained for callers/tests that have only a file set (no scan). */
export function resolveImport(fromRel: string, spec: string, fileSet: Set<string>): string | undefined {
  const r = engineResolveImport(fromRel, extOf(fromRel), spec, ctxFromFileSet(fileSet));
  return r.kind === "resolved" && r.target !== fromRel ? r.target : undefined;
}
