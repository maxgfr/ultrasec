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
//
// This module is the ONE definition of what counts as a secret in free text.
// The council (`council/redact.ts`) used to carry its own `redactSecrets` with
// other rules and another marker; after two branches merged, the same literal
// could be masked in a stage note and survive in a reviewer's report. Council
// code now only adds the plumbing its output needs (JSONL event streams) and
// picks a `BareRuns` level below — never a pattern of its own.
//
// ── The masking convention ──────────────────────────────────────────────────
// A masked value keeps a short prefix and ends in `…` (`Sup3…`, `eyJh…`,
// `$argon2id$v=19$m=65536,t=3,p=4$…`, `postgres://app:…@db`):
//  - a reviewer can still tell two values apart, or see that a cited value is
//    the `AgB…` of a SealedSecret or the `sk_l…` of a live Stripe key;
//  - `…` is outside every value alphabet below, so a masked value is never
//    re-matched and redaction is idempotent (an apply that runs twice, a merge
//    that re-redacts the notes it carries, all leave the text byte-identical);
//  - it is NOT one of the shapes the council's `placeholderArtefacts` flags
//    (`SECRETGATE_<hex>`, `REDACTED`, `***`). A reviewer's report is redacted
//    on the way into `out.md` and parsed again later; a marker the parser read
//    as "a placeholder the code was shown with" would get every redacted claim
//    discarded. That is why a URI password is `…`, not `****`.

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
// `token === undefined` stays readable. A quoted value runs to its closing
// quote — a passphrase has spaces — an unquoted one, or one whose closing quote
// was cut off, stops at whitespace or punctuation.
const NAMED_VALUE =
  /(["'`]?)\b([\w.-]*(?:secret|token|passwd|password|api[_-]?key|private[_-]?key|access[_-]?key|client[_-]?key)[\w.-]*)\1(\s*(?::|=(?![=>]))\s*)(?:(["'`])([^"'`\n]+)\4|(["'`]?)([^\s"'`,;)}\]]+))/gi;

// Env-file / shell style `STRIPE_KEY=…`, `KEY=…`: a bare KEY word is too common
// in code (`sortKey`, `keyboard`) to key on case-insensitively, but an
// upper-case `_KEY` variable assigned with `=` is a credential in practice.
const ENV_KEY = /\b((?:[A-Z][A-Z0-9]*_)*KEY(?:_[A-Z0-9]+)*)=(?![=>])(["'`]?)([^\s"'`,;)}\]]+)/g;

// Values next to a credential name that are not the credential: a reference to
// where it comes from (`process.env.X`, `os.getenv(…)`, `${VAR}`, `req.body.password`),
// a template placeholder, an already-masked value, and the handful of words that
// are never a credential. Masking those would destroy the very argument a
// refutation note makes ("the key is read from the environment").
const NOT_A_VALUE = new Set(["none", "null", "nil", "undefined", "true", "false", "empty", "unset", "required", "optional", "redacted", "masked"]);

function isReference(value: string): boolean {
  if (/[…*]/.test(value) || NOT_A_VALUE.has(value.toLowerCase())) return true;
  // A marker, ours or another tool's: `‹redacted›` (what the council wrote before
  // this module was shared), `‹REDACTED:jwt›` (the log analyzer), and a
  // `SECRETGATE_<hex>` placeholder — an artefact of how the code was SHOWN,
  // which the council's claim parser must still be able to see and flag.
  if (/^(?:‹|SECRETGATE_)/i.test(value)) return true;
  // A password hash: `redactPasswordHashes` already masked it and kept its cost
  // list, which a comma cuts this capture short of.
  if (/^\$(?:argon2|2[abxy]\$|scrypt|pbkdf2)/.test(value)) return true;
  if (/^(?:\$\{|\$[A-Za-z_]\w*$|\{\{|<|%)/.test(value)) return true;
  // A member access or call on identifiers. A JWT (`eyJ….eyJ….sig`) is dotted
  // too, so a segment that long, or one that opens like a JWT, is a value.
  const chain = /^[A-Za-z_$][\w$]*(?:\??\.[A-Za-z_$][\w$]*)+(?:\(.*|\[.*)?$|^[A-Za-z_$][\w$]*[([].*$/;
  return chain.test(value) && !/\beyJ/.test(value) && value.split(/[.([]/).every((seg) => seg.length <= 40);
}

// A JWT: three base64url segments, the first opening on `{"` (`eyJ`). Looser
// than the log analyzer's (8-char segments, not 10) so it covers both shapes the
// two former rule sets knew; the analyzer's own entry is therefore not reused.
const JWT = /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{5,}/g;

// Provider token shapes that need no name in front of them — the log analyzer's
// list, so a shape learned there is masked here too. Its private-key and
// query-string entries are covered above by fuller rules.
const PROVIDER_TOKENS = [JWT, ...SECRET_PATTERNS.filter((p) => ["aws-access-key", "slack-token", "google-api-key"].includes(p.kind)).map((p) => p.re)];
const AUTH_HEADER = /(Authorization:\s*(?:Bearer|Basic)\s+)([^\s"'`]+)/gi;

// ── Bare runs: an opaque string with no name and no known shape ─────────────
// Whether one is a secret depends on WHAT the text is, so the caller picks how
// far to go. One table, so the three answers are decided — and tested — here:
//
//  "keep"          Notes and prose folded into the dossier (stage notes, exploit
//                  paths, investigate write-ups). They carry evidence the engine
//                  needs whole: `fixed in <40-hex sha>` (revalidate writes it),
//                  finding ids, digests, the ciphertext a SealedSecret citation
//                  quotes. A credential in a note nearly always has a name or a
//                  shape, which the rules above catch.
//  "key-material"  A reviewer's report and event stream (council). The reviewer
//                  quotes the files it read, verbatim, from a snapshot with no
//                  git history: a long run there is far likelier a key than a
//                  commit. A run of 32+ base64/hex characters is masked when it
//                  looks like key material (see `looksLikeKeyMaterial`).
//  "opaque"        The cited line of a credential finding (REVALIDATE.todo.json).
//                  The line IS the secret: any run of 20+ characters mixing
//                  digits and letters is masked, slashes and UUIDs included.
//
// `SECRETGATE_<hex>` is never masked at any level: the claim parser must see it.
export type BareRuns = "keep" | "key-material" | "opaque";

/** Slashes excluded on purpose — they are what make a long path look like base64. */
const KEY_MATERIAL_RUN = /(?<![A-Za-z0-9+_=-])[A-Za-z0-9+_=-]{32,}(?![A-Za-z0-9+_=-])/g;
/** Slashes included: a base64 secret on a credential line often has them. */
const OPAQUE_RUN = /[A-Za-z0-9+/=_-]{20,}/g;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function looksLikeKeyMaterial(token: string): boolean {
  if (/^SECRETGATE_/i.test(token)) return false;
  if (UUID.test(token)) return false;
  if (/^[0-9a-f]{32,}$/i.test(token)) return true; // hex digest / key
  const digits = (token.match(/[0-9]/g) ?? []).length;
  const letters = (token.match(/[A-Za-z]/g) ?? []).length;
  // A long camelCase identifier has one or two digits at most; generated key
  // material has many. Four of each separates them on every sample we have.
  return digits >= 4 && letters >= 4;
}

function maskBareRuns(text: string, level: BareRuns): string {
  if (level === "key-material") return text.replace(KEY_MATERIAL_RUN, (run) => (looksLikeKeyMaterial(run) ? maskValue(run) : run));
  if (level === "opaque") {
    // A long CONSTANT_NAME or a path segment has no digit.
    return text.replace(OPAQUE_RUN, (run) => (!/^SECRETGATE_/i.test(run) && /\d/.test(run) && /[A-Za-z]/.test(run) ? maskValue(run) : run));
  }
  return text;
}

export interface RedactOptions {
  /** How far to trust a bare opaque run to be a secret. Default `"keep"`. */
  bareRuns?: BareRuns;
}

/**
 * Mask the credentials a piece of free text can carry, keeping the text around
 * them: modular-crypt password hashes (algorithm and cost kept), PEM private
 * key bodies, URI userinfo passwords, the value of `NAME=value` /
 * `NAME: value` / `"name": "value"` where NAME names a secret, token, password
 * or key, an env-style `…_KEY=value`, an `Authorization:` header's credential,
 * the token shapes (JWT, AWS, Slack, Google) that need no name — and, per
 * `bareRuns`, opaque runs that have neither.
 *
 * Idempotent — a masked value is recognised and left alone — so an apply that
 * runs it twice still leaves the dossier byte-identical.
 */
export function redactSecrets(text: string, opts: RedactOptions = {}): string {
  if (!text) return text;
  const out = redactPasswordHashes(text)
    .replace(PEM_KEY, (_m, begin: string, end: string) => `${begin}…${end}`)
    .replace(URI_USERINFO, (_m, scheme: string, user: string) => `${scheme}${user}:…@`)
    .replace(NAMED_VALUE, (match, q1: string, name: string, sep: string, ...v: (string | undefined)[]) => {
      const [closed, quoted, open = "", bare] = v;
      const value = quoted ?? bare ?? "";
      if (value.length < 4 || isReference(value)) return match;
      return quoted !== undefined ? `${q1}${name}${q1}${sep}${closed}${maskValue(value)}${closed}` : `${q1}${name}${q1}${sep}${open}${maskValue(value)}`;
    })
    .replace(ENV_KEY, (match, name: string, q: string, value: string) => (value.length < 4 || isReference(value) ? match : `${name}=${q}${maskValue(value)}`))
    .replace(AUTH_HEADER, (match, head: string, value: string) => (/[…*]/.test(value) ? match : `${head}${maskValue(value)}`));
  const shaped = PROVIDER_TOKENS.reduce((acc, re) => acc.replace(re, (token) => maskValue(token)), out);
  return maskBareRuns(shaped, opts.bareRuns ?? "keep");
}

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
 * A cited line of a credential finding, safe to put in a worklist: every rule
 * of `redactSecrets` plus the `"opaque"` bare-run level — a bare token in a
 * string literal has no `NAME=` to key on, and for these findings the line is
 * the secret. What survives is the shape — enough to say "still there at HEAD".
 */
export function redactCredentialLine(line: string): string {
  return redactSecrets(line, { bareRuns: "opaque" });
}
