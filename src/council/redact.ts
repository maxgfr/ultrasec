import { redactPasswordHashes } from "../authtokens.js";

// Everything a council reviewer says passes through here before it is written
// into the run directory or printed.
//
// A reviewer reads the code under audit, and the code under audit holds
// secrets: committed `.env.example` files with real values, seed files with
// password hashes, test fixtures with live tokens. Its report quotes them back
// as "evidence", and its JSON event stream carries every file it read, verbatim.
// The run directory is the thing that gets zipped and handed to the client, so a
// literal that reaches it has been published. `authtokens.ts` already learned
// this once — two complete argon2id hashes of a `super` account ended up in a
// shared report — and its redaction is reused rather than re-derived.

/** What a redacted value is replaced with. Deliberately NOT one of the
 *  placeholder shapes `placeholderArtefacts` looks for: re-parsing an `out.md`
 *  this module already redacted must not flag our own marker as an artefact. */
export const REDACTED = "‹redacted›";

/** `NAME=value` in env-file / shell style, NAME naming a secret. The value stops
 *  at whitespace or a quote, so a JSON string containing it stays valid JSON. */
const ENV_ASSIGN = /\b((?:[A-Z][A-Z0-9_]*)?(?:SECRET|TOKEN|PASSWORD|PASSWD|KEY)[A-Z0-9_]*)=(["']?)([^\s"'`]+)\2/g;

/** `"jwt_secret": "…"` / `password: '…'` — only QUOTED values, so code that
 *  merely names the field (`password: req.body.password`) is left readable. */
const KEYED_LITERAL =
  /((?:[A-Za-z0-9_-]*)(?:secret|token|passw(?:or)?d|api[_-]?key|private[_-]?key|access[_-]?key|client[_-]?key)[A-Za-z0-9_-]*["']?\s*[:=]\s*)(["'])([^"'\n]{4,})\2/gi;

/** A JWT: three base64url segments, the first two decoding to JSON objects. */
const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;

/** A run of base64/hex alphabet long enough to be key material. Slashes are
 *  excluded on purpose — they are what make a long path look like base64. */
const LONG_TOKEN = /(?<![A-Za-z0-9+_=-])[A-Za-z0-9+_=-]{32,}(?![A-Za-z0-9+_=-])/g;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** A value that REFERS to a secret rather than being one: `process.env.X`,
 *  `${VAR}`, `$VAR`, `<your-key>`. Redacting it only makes evidence unreadable. */
function isReference(value: string): boolean {
  return /^(?:process\.env|os\.environ|os\.getenv|env\.|\$|\{|<|‹redacted›|SECRETGATE_)/.test(value);
}

function looksLikeKeyMaterial(token: string): boolean {
  if (token.startsWith("SECRETGATE_")) return false; // an artefact to SEE, not a secret
  if (UUID.test(token)) return false;
  if (/^[0-9a-f]{32,}$/i.test(token)) return true; // hex digest / key
  const digits = (token.match(/[0-9]/g) ?? []).length;
  const letters = (token.match(/[A-Za-z]/g) ?? []).length;
  // A long camelCase identifier has one or two digits at most; generated key
  // material has many. Four of each separates them on every sample we have.
  return digits >= 4 && letters >= 4;
}

/** Replace every secret-looking literal in free text. Idempotent. */
export function redactSecrets(text: string): string {
  let out = redactPasswordHashes(text);
  out = out.replace(JWT, REDACTED);
  out = out.replace(ENV_ASSIGN, (whole, name: string, q: string, value: string) => (isReference(value) ? whole : `${name}=${q}${REDACTED}${q}`));
  out = out.replace(KEYED_LITERAL, (whole, head: string, q: string, value: string) => (isReference(value) ? whole : `${head}${q}${REDACTED}${q}`));
  out = out.replace(LONG_TOKEN, (token) => (looksLikeKeyMaterial(token) ? REDACTED : token));
  return out;
}

/** Deep-redact every string inside a parsed JSON value. */
function redactValue(v: unknown): unknown {
  if (typeof v === "string") return redactSecrets(v);
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
    return redactSecrets(line);
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
