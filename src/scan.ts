import { walk, readText } from "./walk.js";
import { langForFile, extract, type Sym, type Imp, type Call } from "./lang.js";
import { byStr } from "./util.js";

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
}

export interface ScanOptions {
  maxBytes?: number;
}

/** Walk the repo and extract symbols/imports/calls from every recognized file. */
export function scanRepo(repo: string, opts: ScanOptions = {}): RepoScan {
  const files: FileScan[] = [];
  for (const wf of walk(repo, { maxBytes: opts.maxBytes })) {
    const spec = langForFile(wf.rel);
    if (!spec) continue;
    const { symbols, imports, calls } = extract(spec, readText(wf.abs));
    files.push({ rel: wf.rel, lang: spec.id, symbols, imports, calls });
  }
  files.sort((a, b) => byStr(a.rel, b.rel));
  return { repo, files };
}
