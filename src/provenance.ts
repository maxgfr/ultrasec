import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { globToRe } from "./walk.js";
import { blameLine, type BlameInfo } from "./git.js";
import type { CodeLoc, Finding, Provenance } from "./types.js";

// Deterministic, keyless provenance enrichment — ultrasec's analogue of deepsec's
// `enrich` stage. For each finding it attaches WHO last touched the line (git
// blame), WHEN (the commit's author-date, reproducible), and WHICH team owns the
// file (CODEOWNERS). It is a triage signal, never a suppression rule: ultrasec's
// conservative gate must not drop a finding because the code looks old.

export interface OwnerRule {
  re: RegExp;
  owners: string[];
}

// CODEOWNERS uses gitignore-style patterns with "last match wins". We translate a
// pattern to the same matcher the walker uses (`globToRe`), handling anchoring:
// a pattern with a slash anywhere (except a trailing one) is anchored to the repo
// root; a pattern with no internal slash matches at any depth (prefix "**/").
function compileCodeowner(pattern: string): RegExp {
  const dirOnly = pattern.endsWith("/") && pattern.length > 1;
  let core = dirOnly ? pattern.slice(0, -1) : pattern;
  const leadingSlash = core.startsWith("/");
  if (leadingSlash) core = core.slice(1);
  const anchored = leadingSlash || core.includes("/");
  const glob = (anchored ? core : "**/" + core) + (dirOnly ? "/" : "");
  return globToRe(glob);
}

/** Parse CODEOWNERS into ORDERED rules (source order — last match wins). */
export function parseCodeowners(content: string): OwnerRule[] {
  const rules: OwnerRule[] = [];
  for (const raw of content.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, "").trim(); // strip comments (full-line + trailing)
    if (!line) continue;
    const parts = line.split(/\s+/);
    const pattern = parts[0]!;
    const owners = parts.slice(1).filter(Boolean);
    if (!pattern || !owners.length) continue;
    rules.push({ re: compileCodeowner(pattern), owners });
  }
  return rules;
}

/** The owners for `file`, or `undefined` — the LAST matching rule wins. */
export function ownerFor(rules: OwnerRule[], file: string): string[] | undefined {
  let owners: string[] | undefined;
  for (const r of rules) if (r.re.test(file)) owners = r.owners;
  return owners;
}

const CODEOWNERS_PATHS = [".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"];

/** Load the repo's CODEOWNERS (first of the three conventional locations). */
export function loadCodeowners(repo: string): OwnerRule[] {
  for (const p of CODEOWNERS_PATHS) {
    const abs = join(repo, p);
    if (existsSync(abs)) {
      try {
        return parseCodeowners(readFileSync(abs, "utf8"));
      } catch {
        return [];
      }
    }
  }
  return [];
}

export interface ProvenanceOptions {
  /** Run `git blame` per finding (author/commit/date). CODEOWNERS owners attach regardless. */
  blame?: boolean;
}

/** The line a finding is anchored to — its sink, else its source, else its path tail. */
function primaryLoc(f: Finding): CodeLoc | undefined {
  if (f.sink) return f.sink;
  if (f.source) return f.source;
  if (f.path && f.path.length) return f.path[f.path.length - 1];
  return undefined;
}

/**
 * Attach {@link Provenance} to each finding from its primary location. Pure
 * w.r.t. the finding set (returns new objects); offline-tolerant (no git / no
 * CODEOWNERS ⇒ findings pass through unchanged). Blame is cached per file:line.
 */
export function addProvenance(findings: Finding[], repo: string, opts: ProvenanceOptions = {}): Finding[] {
  const owners = loadCodeowners(repo);
  const blameCache = new Map<string, BlameInfo | null>();
  return findings.map((f) => {
    const loc = primaryLoc(f);
    if (!loc) return f;
    const prov: Provenance = {};
    const own = ownerFor(owners, loc.file);
    if (own && own.length) prov.owner = own.join(", ");
    if (opts.blame) {
      const key = `${loc.file}:${loc.line}`;
      let b = blameCache.get(key);
      if (b === undefined) blameCache.set(key, (b = blameLine(repo, loc.file, loc.line)));
      if (b) {
        if (b.author) prov.author = b.author;
        if (b.commit) prov.commit = b.commit;
        if (b.date) prov.date = b.date;
      }
    }
    return Object.keys(prov).length ? { ...f, provenance: prov } : f;
  });
}
