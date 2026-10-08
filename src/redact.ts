import type { Finding } from "./types.js";
import { SECRET_PATTERNS } from "./logs/secrets.js";

// ── Redaction of credentials in text the dossier echoes ─────────────────────
// Every string folded into findings.json is echoed again into DOSSIER.md and
// the rendered REPORT.md/index.html — documents written to be passed around.
// The engine's own evidence was the first leak (two argon2id hashes of a `super`
// account in a real report); the second was the auditor's prose. A revalidation
// note quoted the cited line from REVALIDATE.todo.json, the line was a seed
// row, and the full hash went into the report the detector had just been fixed
// to keep it out of. Whoever writes the text, it goes through here first.

/**
 * A password hash with its salt and digest masked: the algorithm and its cost
 * parameters stay — they are what the finding is about — the crackable part
 * does not. The evidence line is echoed into findings.json, DOSSIER.md and the
 * rendered REPORT.md/index.html; on a real audit that put two complete argon2id
 * hashes of a `super` account into a report written to be passed around.
 */
export function redactPasswordHashes(text: string): string {
  // The literal's own alphabet (base64, cost lists like `m=65536,t=3,p=4`), so a
  // closing quote or bracket ends it — a comma does not, or the salt and digest
  // after the cost list would survive.
  return text.replace(/\$(argon2(?:id|i|d)?|2[abxy]|scrypt|pbkdf2[\w-]*)\$[\w./+=,$-]*/g, (literal: string, algo: string, at: number, whole: string) => {
    // Already masked: the `…` is outside the literal's alphabet, so the match
    // stops right before it. Re-masking would stack a second `…` on every pass,
    // and a merge re-redacts the notes it carries.
    if (whole[at + literal.length] === "…") return literal;
    const kept = [algo];
    for (const part of literal.split("$").slice(2)) {
      // Version and cost segments: `v=19`, `m=65536,t=3,p=4`, scrypt's `ln=16,r=8,p=1`,
      // bcrypt's `12`, pbkdf2's `29000` iterations.
      if (/^(?:[a-z]+=\d+(?:,[a-z]+=\d+)*|\d{1,7})$/.test(part)) kept.push(part);
      else break;
    }
    return `$${kept.join("$")}$…`;
  });
}

/** Keep a short prefix — enough to tell two values apart in a review, never
 *  enough to use one. A short value keeps less, or it would keep all of it. */
function maskValue(value: string): string {
  return `${value.slice(0, Math.min(4, Math.floor(value.length / 3)))}…`;
}

// A PEM private key, armour and all. An unterminated block (a quote cut at 160
// or 200 characters) is masked to the end of the text: the cut is exactly where
// a quoted key usually stops.
const PEM_KEY = /(-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----)[\s\S]*?(-----END [A-Z0-9 ]*PRIVATE KEY-----|$)/g;

// `scheme://user:password@host` — the userinfo password, never the user or host,
// which are what tells a reviewer WHICH service the credential opens.
const URI_USERINFO = /\b([a-z][a-z0-9+.-]*:\/\/)([^\s:@/]*):([^\s@/]+)@/gi;

// `NAME=value`, `NAME: value`, `"name": "value"` where NAME names a credential.
// `=` must not be a comparison (`==`, `===`) or an arrow (`=>`), so a quoted
// `token === undefined` stays readable.
const NAMED_VALUE = /(["'`]?)\b([\w.-]*(?:secret|token|passwd|password|api_?key|private_?key)[\w.-]*)\1(\s*(?::|=(?![=>]))\s*)(["'`]?)([^\s"'`,;)}\]]+)/gi;

// Values next to a credential name that are not the credential: a reference to
// where it comes from (`process.env.X`, `os.getenv(…)`, `${VAR}`, `req.body.password`),
// a template placeholder, an already-masked value, and the handful of words that
// are never a credential. Masking those would destroy the very argument a
// refutation note makes ("the key is read from the environment").
const NOT_A_VALUE = new Set(["none", "null", "nil", "undefined", "true", "false", "empty", "unset", "required", "optional", "redacted", "masked"]);

function isReference(value: string): boolean {
  if (/[…*]/.test(value) || NOT_A_VALUE.has(value.toLowerCase())) return true;
  // A password hash: `redactPasswordHashes` already masked it and kept its cost
  // list, which a comma cuts this capture short of.
  if (/^\$(?:argon2|2[abxy]\$|scrypt|pbkdf2)/.test(value)) return true;
  if (/^(?:\$\{|\$[A-Z_][A-Z0-9_]*$|\{\{|<|%)/.test(value)) return true;
  // A member access or call on identifiers. A JWT (`eyJ….eyJ….sig`) is dotted
  // too, so a segment that long, or one that opens like a JWT, is a value.
  const chain = /^[A-Za-z_$][\w$]*(?:\??\.[A-Za-z_$][\w$]*)+(?:\(.*|\[.*)?$|^[A-Za-z_$][\w$]*[([].*$/;
  return chain.test(value) && !/\beyJ/.test(value) && value.split(/[.([]/).every((seg) => seg.length <= 40);
}

// Provider token shapes that need no name in front of them — the log analyzer's
// list, so a shape learned there is masked here too. Its private-key and
// query-string entries are covered above by fuller rules.
const PROVIDER_TOKENS = SECRET_PATTERNS.filter((p) => ["aws-access-key", "jwt", "slack-token", "google-api-key"].includes(p.kind)).map((p) => p.re);
const AUTH_HEADER = /(Authorization:\s*(?:Bearer|Basic)\s+)([^\s"'`]+)/gi;

/**
 * Mask the credentials a piece of free text can carry, keeping the text around
 * them: modular-crypt password hashes (algorithm and cost kept), PEM private
 * key bodies, URI userinfo passwords, the value of `NAME=value` /
 * `NAME: value` where NAME names a secret, token, password or key, an
 * `Authorization:` header's credential, and the provider token shapes (AWS,
 * JWT, Slack, Google) that need no name.
 *
 * Idempotent — a masked value is recognised and left alone — so an apply that
 * runs it twice still leaves the dossier byte-identical.
 */
export function redactSecrets(text: string): string {
  if (!text) return text;
  const out = redactPasswordHashes(text)
    .replace(PEM_KEY, (_m, begin: string, end: string) => `${begin}…${end}`)
    .replace(URI_USERINFO, (_m, scheme: string, user: string) => `${scheme}${user}:****@`)
    .replace(NAMED_VALUE, (match, q1: string, name: string, sep: string, q2: string, value: string) =>
      value.length < 4 || isReference(value) ? match : `${q1}${name}${q1}${sep}${q2}${maskValue(value)}`,
    )
    .replace(AUTH_HEADER, (match, head: string, value: string) => (/[…*]/.test(value) ? match : `${head}${maskValue(value)}`));
  return PROVIDER_TOKENS.reduce((acc, re) => acc.replace(re, (token) => maskValue(token)), out);
}

// Long opaque runs — an API token, a base64 key — with no name in front of them.
// A run needs a digit and a letter: a long CONSTANT_NAME or a path has no digit.
const OPAQUE_TOKEN = /[A-Za-z0-9+/=_-]{20,}/g;

/**
 * The finding is ABOUT a credential: a secret scanner's hit, or a CWE that names
 * a hard-coded or weakly-stored one. For these the cited line IS the secret, so
 * quoting it anywhere is the leak the finding reports.
 */
export function isCredentialFinding(f: Pick<Finding, "category" | "cwe" | "title">): boolean {
  if (f.category === "secret") return true;
  const credentialCwe = /\bCWE-(?:798|259|321|522|916)\b/;
  return credentialCwe.test(f.cwe ?? "") || credentialCwe.test(f.title);
}

/**
 * A cited line of a credential finding, safe to put in a worklist. On top of
 * `redactSecrets`, any long opaque run is masked: a bare token in a string
 * literal has no `NAME=` to key on, and for these findings the line is the
 * secret. What survives is the shape — enough to say "still there at HEAD".
 */
export function redactCredentialLine(line: string): string {
  return redactSecrets(line).replace(OPAQUE_TOKEN, (run) => (/\d/.test(run) && /[A-Za-z]/.test(run) ? maskValue(run) : run));
}
