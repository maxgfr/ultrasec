import { join } from "node:path";
import { readText } from "./walk.js";
import { localDefNames, type RepoScan } from "./scan.js";
import { langForFile } from "./lang.js";
import { findSinks, findTextSinks, type SinkHit, type SinkRule } from "./catalog.js";

/**
 * Per-file facts a scan derives more than once, computed at most once per run.
 *
 * The taint pass, the orphan-sink pass and the logging-hygiene pass each read
 * every source file, split it into lines and match its calls against the sink
 * catalog — the same three answers, produced three times behind three private
 * caches. This is the one place those answers live for the life of a scan. It
 * is created per run and handed to each pass as an option; a pass called on its
 * own (tests, the MCP tools) creates its own and behaves exactly as before.
 *
 * Everything here is a pure function of the scan, so sharing it cannot change a
 * result — only how many times it is computed. The returned arrays are shared:
 * callers copy before they mutate.
 */
export interface FileFacts {
  /** File content, `""` when unreadable (as `readText`). */
  content(rel: string): string;
  /** `content(rel).split(/\r?\n/)`. */
  lines(rel: string): string[];
  /** Call-shaped sink hits (`findSinks`), keyed on the identity of `extraSinks`. */
  sinks(rel: string, extraSinks?: SinkRule[]): SinkHit[];
  /** Assignment-shaped sink hits (`findTextSinks`). */
  textSinks(rel: string): SinkHit[];
  /** Callables the file defines itself (`localDefNames`). */
  localDefs(rel: string): ReadonlySet<string>;
}

const NO_EXTRA: SinkRule[] = [];
const EMPTY_HITS: SinkHit[] = [];
const EMPTY_DEFS: ReadonlySet<string> = new Set();

export function createFileFacts(scan: RepoScan): FileFacts {
  const byRel = new Map(scan.files.map((f) => [f.rel, f]));
  const contents = new Map<string, string>();
  const lineCache = new Map<string, string[]>();
  const defCache = new Map<string, ReadonlySet<string>>();
  const textSinkCache = new Map<string, SinkHit[]>();
  // extraSinks identity → rel → hits. `undefined` extras share one bucket.
  const sinkCache = new Map<SinkRule[], Map<string, SinkHit[]>>();

  const content = (rel: string): string => {
    let c = contents.get(rel);
    if (c === undefined) contents.set(rel, (c = readText(join(scan.repo, rel))));
    return c;
  };
  const lines = (rel: string): string[] => {
    let l = lineCache.get(rel);
    if (!l) lineCache.set(rel, (l = content(rel).split(/\r?\n/)));
    return l;
  };
  const localDefs = (rel: string): ReadonlySet<string> => {
    let d = defCache.get(rel);
    if (!d) {
      const file = byRel.get(rel);
      defCache.set(rel, (d = file ? localDefNames(file.symbols) : EMPTY_DEFS));
    }
    return d;
  };
  const sinks = (rel: string, extraSinks?: SinkRule[]): SinkHit[] => {
    const key = extraSinks && extraSinks.length ? extraSinks : NO_EXTRA;
    let bucket = sinkCache.get(key);
    if (!bucket) sinkCache.set(key, (bucket = new Map()));
    let hits = bucket.get(rel);
    if (!hits) {
      const file = byRel.get(rel);
      const lang = langForFile(rel);
      hits = file && lang ? findSinks(lang, file.calls, extraSinks, file.imports, localDefs(rel), lines(rel)) : EMPTY_HITS;
      bucket.set(rel, hits);
    }
    return hits;
  };
  const textSinks = (rel: string): SinkHit[] => {
    let hits = textSinkCache.get(rel);
    if (!hits) {
      const lang = langForFile(rel);
      hits = lang ? findTextSinks(lang, content(rel)) : EMPTY_HITS;
      textSinkCache.set(rel, hits);
    }
    return hits;
  };

  return { content, lines, sinks, textSinks, localDefs };
}
