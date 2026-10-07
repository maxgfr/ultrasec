// Idiom vocabulary several packs share. Data, not logic: a regex that more
// than one pack needs lives here once, so two packs cannot drift on what, say,
// "this file mentions CSV" means.

/** The file produces or names CSV. */
export const MENTIONS_CSV = /text\/csv|\.csv\b|\bcsv\b/i;

/**
 * A formula-neutralizing step: a character class or literal list holding both
 * `=` and `+`, or a helper named for it. The original JavaScript detector's
 * test, kept byte-identical for the Node pack.
 */
export const NEUTRALIZES_FORMULA =
  /\[[^\]\n]*=[^\]\n]*\+[^\]\n]*\]|\[[^\]\n]*\+[^\]\n]*=[^\]\n]*\]|["']=["']\s*,\s*["']\+["']|formula|neutrali[sz]|csv-?injection|escapeCsv|sanitizeCsv/i;

/** The same, plus the prefix tests and libraries other languages write it with. */
export const NEUTRALIZES_FORMULA_ANY = new RegExp(
  `${NEUTRALIZES_FORMULA.source}|(?:startswith|start_with\\?|str_starts_with|HasPrefix|startsWith)\\s*\\(?[^)\\n]*["'][=+@-]|defusedcsv|escape_formula|sanitize_?csv`,
  "i",
);

/** X-Forwarded-For named the way each stack reads it. */
export const XFF = /x-forwarded-for|HTTP_X_FORWARDED_FOR|X_FORWARDED_FOR/i;

/** How many lines above a first-hop extraction the header may be read. */
export const XFF_LOOKBACK = 5;

/** A path segment that says "this route serves a bulk export or public listing". */
export const EXPORT_PATH = /(?:^|[/._-])(?:public|export|exports|download|downloads|csv|xlsx|feed|dump)(?:[/._-]|$)/i;

/** A security-headers middleware, across ecosystems (the original detector's list). */
export const HEADERS_MIDDLEWARE =
  /\bhelmet\s*\(|\bsecureHeaders\s*\(|\bfastify-helmet\b|@fastify\/helmet|\bsecure_headers\b|\bSecureHeadersMiddleware\b|\bTalisman\s*\(|\bhelmet\.contentSecurityPolicy\b/;

/** A response header that only a security-header setup writes. */
export const SETS_SECURITY_HEADER = /Content-Security-Policy|X-Frame-Options|Strict-Transport-Security/i;

/** A name that says "this boolean is a feature/security switch". */
export const FLAG_NAME = String.raw`\w*(?:enabled|disabled|enable|disable|flag|debug|mock|fake|skip|bypass|allow|insecure|feature|dry_?run|test_?mode)\w*`;
