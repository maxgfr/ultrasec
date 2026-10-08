import { redactSecrets } from "../redact.js";

// Everything a council reviewer says passes through here before it is written
// into the run directory or printed.
//
// A reviewer reads the code under audit, and the code under audit holds
// secrets: committed `.env.example` files with real values, seed files with
// password hashes, test fixtures with live tokens. Its report quotes them back
// as "evidence", and its JSON event stream carries every file it read, verbatim.
// The run directory is the thing that gets zipped and handed to the client, so a
// literal that reaches it has been published.
//
// WHAT counts as a secret is decided in `../redact.ts`, the same rules the
// engine's stage notes go through — this module once had its own, and the same
// literal could be masked in one place and not the other. Here lives only what
// is specific to reviewer output: the bare-run level it is redacted at, the
// JSONL event stream, and the placeholder artefacts a claim can lean on.

/**
 * Redact a reviewer's text: the shared rules, plus bare runs that look like key
 * material (`"key-material"`, see `BareRuns` in `../redact.ts` for why notes
 * are not held to it). The mask (`Sup3…`) is deliberately none of the shapes
 * `placeholderArtefacts` flags, so re-parsing an `out.md` this module already
 * redacted never takes our own marker for a masking placeholder.
 */
export function redactReviewerText(text: string): string {
  return redactSecrets(text, { bareRuns: "key-material" });
}

/** Deep-redact every string inside a parsed JSON value. */
function redactValue(v: unknown): unknown {
  if (typeof v === "string") return redactReviewerText(v);
  if (Array.isArray(v)) return v.map(redactValue);
  if (v && typeof v === "object") {
    const o: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(v)) o[k] = redactValue(val);
    return o;
  }
  return v;
}

/**
 * Redact one line of a JSONL event stream.
 *
 * Done on the PARSED value, never on the raw line: inside a JSON string a
 * newline is `\n`, and a regex that starts a token on that `n` and replaces it
 * leaves a lone backslash — an invalid escape that turns the whole events file
 * into something no later `--parse` can read. A line that is not JSON is
 * redacted as text.
 */
export function redactJsonLine(line: string): string {
  try {
    return JSON.stringify(redactValue(JSON.parse(line)));
  } catch {
    return redactReviewerText(line);
  }
}

/**
 * Secret-MASKING placeholders a claim mentions.
 *
 * On a real audit a reviewer reported, as a finding, that a production JWT
 * secret had been "replaced by a SECRETGATE placeholder". It had — by the
 * orchestrator's own secret-masking hook, on the way into the reviewer's
 * context. A placeholder is an artefact of how the code was SHOWN, never a fact
 * about the code, so a claim built on one is flagged for the orchestrator to
 * discard rather than verify.
 */
export function placeholderArtefacts(text: string): string[] {
  const hits = new Set<string>();
  for (const m of text.matchAll(/\bSECRETGATE_[0-9a-f]+\b/gi)) hits.add(`${m[0].slice(0, 16)}…`);
  if (/\bREDACTED\b/.test(text)) hits.add("REDACTED");
  // `***` as a VALUE (`= ***`, `"***"`), not markdown bold-italic around a word.
  if (/(?<![*\w])\*{3,}(?![*\w])/.test(text)) hits.add("***");
  return [...hits].sort();
}
