// Resolve an import specifier from one repo file to another repo file. Heuristic
// and language-agnostic: handles relative paths (JS/TS/Python-style), extension
// guessing and index/package files. External/library specifiers (no leading `.`
// and not matching a repo file) resolve to `undefined` — they become dangling.

const CODE_EXTS = [
  "js",
  "jsx",
  "mjs",
  "cjs",
  "ts",
  "tsx",
  "mts",
  "cts",
  "py",
  "go",
  "java",
  "rb",
  "php",
  "rs",
  "c",
  "h",
  "cc",
  "cpp",
  "hpp",
  "cs",
  "kt",
  "kts",
  "swift",
  "scala",
  "sh",
  "lua",
  "ex",
  "exs",
];
const INDEX_BASENAMES = ["index", "__init__", "mod", "main"];

function dirOf(rel: string): string {
  const i = rel.lastIndexOf("/");
  return i < 0 ? "" : rel.slice(0, i);
}

function normalize(path: string): string {
  const parts: string[] = [];
  for (const seg of path.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") {
      // Pop a real segment, but PRESERVE leading `..` (don't pop past the root)
      // so a spec that escapes the repo stays unresolvable instead of silently
      // collapsing to a wrong in-repo path.
      if (parts.length && parts[parts.length - 1] !== "..") parts.pop();
      else parts.push("..");
    } else parts.push(seg);
  }
  return parts.join("/");
}

/** Build candidate repo-relative paths for a specifier resolved against `fromRel`. */
function candidates(fromRel: string, spec: string): string[] {
  const out: string[] = [];
  let base: string;
  if (spec.startsWith(".")) {
    base = normalize(`${dirOf(fromRel)}/${spec}`);
  } else if (spec.startsWith("/")) {
    base = normalize(spec);
  } else {
    // dotted module path (python/java/go-ish): a/b/c — try as a repo subpath too
    base = spec.replace(/[.\\]/g, "/").replace(/^@/, "");
  }
  out.push(base);
  for (const ext of CODE_EXTS) out.push(`${base}.${ext}`);
  for (const idx of INDEX_BASENAMES) for (const ext of CODE_EXTS) out.push(`${base}/${idx}.${ext}`);
  return out;
}

export function resolveImport(fromRel: string, spec: string, fileSet: Set<string>): string | undefined {
  for (const c of candidates(fromRel, spec)) {
    if (fileSet.has(c)) return c;
  }
  return undefined;
}
