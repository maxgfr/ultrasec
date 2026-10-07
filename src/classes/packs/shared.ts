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

// ── Cookie flags, read the way the original detector read them ──────────────
// (src/webconfig.ts up to v1.58.0): one call head, its balanced argument text,
// one finding per flag the options lack. Shared by the Node and PHP packs so
// both keep that detector's findings exactly.

/** The cookie-writing calls of Express, Fastify, Koa, Next.js and PHP. */
export const COOKIE_CALL = /\b(?:res(?:ponse)?\.cookie|reply\.setCookie|ctx\.cookies\.set|cookies\.set|setcookie)\s*\(/gi;

/** `flag: <expression>` — bound to something other than a literal: SET, to whatever the deployment decides. */
const boundFlag = (flag: string): string => String.raw`\b${flag}\s*:\s*(?!(?:false|0|null|undefined|true|1)\b)[!A-Za-z_$(]`;

export const COOKIE_HTTPONLY_SET = new RegExp(String.raw`httponly\s*[:=]?\s*(?:true|1)|['"]httponly['"]\s*=>\s*true|${boundFlag("httponly")}`, "i");
export const COOKIE_SECURE_SET = new RegExp(String.raw`\bsecure\s*[:=]?\s*(?:true|1)|['"]secure['"]\s*=>\s*true|${boundFlag("secure")}`, "i");
export const COOKIE_SAMESITE_SET = /samesite\s*[:=]?\s*['"]?(?:strict|lax|none)|['"]samesite['"]\s*=>\s*['"]?(?:strict|lax|none)/i;
export const COOKIE_SAMESITE_NONE = /samesite\s*[:=]?\s*['"]?none|['"]samesite['"]\s*=>\s*['"]?none/i;

/** The original detector's cookie flags: no options → HttpOnly + Secure; options → each flag it lacks. */
export const LEGACY_COOKIE_FLAGS = {
  options: { args: /\{/, head: /setcookie/i },
  bare: ["webconfig/cookie-httponly", "webconfig/cookie-secure"],
  flags: [
    { emit: "webconfig/cookie-httponly", present: COOKIE_HTTPONLY_SET },
    { emit: "webconfig/cookie-secure", present: COOKIE_SECURE_SET },
    { emit: "webconfig/cookie-samesite", present: COOKIE_SAMESITE_SET },
    { emit: "webconfig/cookie-samesite-none-insecure", when: COOKIE_SAMESITE_NONE, present: COOKIE_SECURE_SET },
  ],
};

/** Express `app.set("trust proxy", …)` with anything but `false` (the original detector's rule). */
export const EXPRESS_TRUST_PROXY = /\.set\s*\(\s*['"]trust proxy['"]\s*,(?!\s*false\b)/;

/** GraphQL introspection / IDE switched on in an options object or a config file (the original detector's rule). */
export const GRAPHQL_INTROSPECTION_ON = /\b(?:introspection|graphiql|playground)\s*:\s*true\b/;
