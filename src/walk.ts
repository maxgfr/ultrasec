import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { byStr } from "./util.js";

// Directories never worth scanning for a security audit (vendored code, build
// output, VCS internals). Kept conservative + deterministic.
const DEFAULT_IGNORE_DIRS = new Set([
  ".git",
  "node_modules",
  "vendor",
  "dist",
  "build",
  "out",
  "target",
  ".next",
  ".nuxt",
  "coverage",
  ".venv",
  "venv",
  "__pycache__",
  ".gradle",
  ".idea",
  ".vscode",
  ".ultrasec",
]);

const MAX_FILE_BYTES = 1_500_000; // skip huge/minified blobs

export interface WalkedFile {
  /** Repo-relative POSIX path. */
  rel: string;
  /** Absolute path. */
  abs: string;
  bytes: number;
}

export interface WalkOptions {
  ignoreDirs?: Set<string>;
  maxBytes?: number;
}

/** Recursively list files under `root`, skipping ignored dirs. Deterministic. */
export function walk(root: string, opts: WalkOptions = {}): WalkedFile[] {
  const ignore = opts.ignoreDirs ?? DEFAULT_IGNORE_DIRS;
  const maxBytes = opts.maxBytes ?? MAX_FILE_BYTES;
  const out: WalkedFile[] = [];

  const visit = (dir: string): void => {
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const name of entries.sort(byStr)) {
      const abs = join(dir, name);
      let st;
      try {
        st = statSync(abs);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        if (ignore.has(name)) continue;
        visit(abs);
      } else if (st.isFile()) {
        if (st.size > maxBytes) continue;
        const rel = relative(root, abs).split(sep).join("/");
        out.push({ rel, abs, bytes: st.size });
      }
    }
  };

  visit(root);
  return out.sort((a, b) => byStr(a.rel, b.rel));
}

export function readText(abs: string): string {
  try {
    return readFileSync(abs, "utf8");
  } catch {
    return "";
  }
}
