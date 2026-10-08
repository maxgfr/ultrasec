// Masking placeholders: values that stand in for a secret because some tool
// masked it before a human or a model saw the text.
//
// The auditor's environment may rewrite tool output on the way into an agent's
// context (a secret-masking hook, a log scrubber, a redacting proxy), and the
// code under audit may itself ship `REDACTED` or `***` in an example file. On a
// real audit a reviewer reported, as a finding, that a production secret had
// been "replaced by a placeholder" — it had, by the orchestrator's own masking
// hook, on the way into the reviewer's context. A placeholder is an artefact of
// how the code was SHOWN, never a fact about the code. Two consequences:
//
//  - the claim parser surfaces every placeholder a claim leans on, so the
//    orchestrator discards the claim instead of verifying it;
//  - redaction never masks one: masked, it would no longer be recognisable, and
//    it is not a secret anyway.
//
// The defaults are generic SHAPES, not one tool's name. A tool with another
// shape is added with `--placeholder-pattern <regex>` or `placeholderPatterns`
// in the council config.

/**
 * Generic placeholder shapes:
 *  - a masked token: an upper-case tool prefix, `_`, then 8–32 lower-case hex
 *    with at least one letter (`MASK_9f3a2b1c`, `SCRUB_TOKEN_ab14…`) — dates and
 *    numeric constants (`BUILD_20240101`) have no hex letter;
 *  - `REDACTED`, `[redacted]`, `<redacted>`;
 *  - `***` as a value (`= ***`, `"***"`), not markdown emphasis around a word;
 *  - `xxxx` and longer runs of x as a value.
 */
export const DEFAULT_PLACEHOLDER_PATTERNS: readonly RegExp[] = [
  /\b[A-Z][A-Z0-9]{2,}(?:_[A-Z0-9]+)*_(?=[0-9a-f]*[a-f])[0-9a-f]{8,32}\b/g,
  /\bREDACTED\b/g,
  /\[redacted\]|<redacted>/gi,
  /(?<![*\w])\*{3,}(?![*\w])/g,
  /(?<![\w])[xX]{4,}(?![\w])/g,
];

/** Compile user-supplied placeholder regexes (case-sensitive, global). Throws on a bad one. */
export function compilePlaceholderPatterns(sources: readonly string[], where: string): RegExp[] {
  return sources.map((src) => {
    if (!src) throw new Error(`${where}: empty placeholder pattern`);
    try {
      return new RegExp(src, "g");
    } catch (e) {
      throw new Error(`${where}: invalid placeholder pattern ${JSON.stringify(src)} (${(e as Error).message})`);
    }
  });
}

const all = (extra: readonly RegExp[]): readonly RegExp[] => (extra.length ? [...DEFAULT_PLACEHOLDER_PATTERNS, ...extra] : DEFAULT_PLACEHOLDER_PATTERNS);

/** A short, stable label for one placeholder occurrence. */
function label(hit: string): string {
  if (/^\*+$/.test(hit)) return "***";
  return hit.length > 16 ? `${hit.slice(0, 16)}…` : hit;
}

/** Every placeholder in `text`, as sorted, de-duplicated labels. */
export function placeholderHits(text: string, extra: readonly RegExp[] = []): string[] {
  const hits = new Set<string>();
  for (const re of all(extra)) {
    for (const m of text.matchAll(new RegExp(re.source, re.flags.includes("g") ? re.flags : `${re.flags}g`))) {
      if (m[0]) hits.add(label(m[0]));
    }
  }
  return [...hits].sort();
}

/** Does `value` open with a placeholder? (A captured value is never a secret then.) */
export function isPlaceholder(value: string, extra: readonly RegExp[] = []): boolean {
  for (const re of all(extra)) {
    const r = new RegExp(re.source, re.flags.replace("g", ""));
    const m = r.exec(value);
    if (m && m.index === 0 && m[0]) return true;
  }
  return false;
}
