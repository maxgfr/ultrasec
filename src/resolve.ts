// Import resolution, delegated to the vendored codeindex engine
// (buildResolveContext + resolveImport). The engine's resolver is a strict
// superset of ultrasec's former heuristic: relative/dotted paths, extension and
// index/package guessing PLUS tsconfig/jsconfig path aliases, package.json
// `exports`, go.mod/replace, Cargo crates, Java/C#/PHP-PSR4 roots. On ultrasec's
// own fixtures it resolves import-for-import identically to the old resolver
// (verified differentially before adoption); on real repos it resolves strictly
// more edges (documented as an accepted, more-correct divergence).
import type { RepoScan } from "./scan.js";
import { buildResolveContext, resolveImport as engineResolveImport, type ResolveContext } from "./vendor/codeindex-engine.mjs";

function extOf(rel: string): string {
  const i = rel.lastIndexOf(".");
  return i < 0 ? "" : rel.slice(i).toLowerCase();
}

/** Adapt ultrasec's RepoScan to the minimal engine scan shape buildResolveContext
 *  consumes: it reads only `root`, and per file `rel`/`ext`/`pkg` (the last two
 *  only for Java/C# namespace roots). Everything else it reads from disk via
 *  `root`. Cast through the engine's expected type — the extra FileRecord fields
 *  are never touched. */
function engineScan(scan: RepoScan): Parameters<typeof buildResolveContext>[0] {
  const files = scan.files.map((f) => ({ rel: f.rel, ext: extOf(f.rel) }));
  return { root: scan.repo, files } as unknown as Parameters<typeof buildResolveContext>[0];
}

/** A repo-file import resolver bound to a scan's full resolve context (tsconfig
 *  paths, workspace exports, module roots). Returns the resolved repo-relative
 *  target, or undefined for external/dangling specifiers. */
export function buildFileResolver(scan: RepoScan): (fromRel: string, spec: string) => string | undefined {
  const ctx = buildResolveContext(engineScan(scan));
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
