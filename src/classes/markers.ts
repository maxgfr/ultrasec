import { PACKS } from "./packs/index.js";
import type { MarkerVocabulary, Pack } from "./types.js";

// The guard vocabulary — what an authentication or a rate-limiting check looks
// like in code — for the guard matrix (`guards.ts`), the context brief and the
// dossier. A match is a CANDIDATE protection site for the auditor to confirm,
// never proof a route is guarded.
//
// Two layers. The FLOOR below is generic: names any stack might give its own
// check (`requireAuth`, `verifyToken`, `rateLimit`). Everything a framework or
// a library spells its own way comes from its pack (`Pack.markers`): names no
// other stack uses are matched everywhere (`global`), names too generic to
// trust elsewhere only where the stack is detected (`detected`) — NextAuth v5's
// `auth()`, a FastAPI `Depends(get_current_user)`.

export type MarkerLens = "auth" | "throttle";

/** Generic authentication/authorization names — the floor every repository gets. */
const AUTH_FLOOR: MarkerVocabulary = {
  words: [
    "requireAuth",
    "requiresAuth",
    "isAuthenticated",
    "ensureAuthenticated",
    "ensureLoggedIn",
    "ensureLogin",
    "requireLogin",
    "checkAuth",
    "verifyToken",
    "verifyJwt",
    "jwtVerify",
    "authenticateToken",
    "authMiddleware",
    "requireRole",
    "requireAdmin",
    "hasRole",
    "hasPermission",
    "checkPermission",
    "authorize",
    "authorization",
  ],
};

/**
 * Generic rate-limiting names. "No throttling anywhere" is a FACT about an
 * application a real audit established with `grep -E 'rate|429'`; `429` earns
 * its place, but only next to a status-shaped context, since a bare 429 in a
 * fixture or a phone number would otherwise read as a protection.
 */
const THROTTLE_FLOOR: MarkerVocabulary = {
  patterns: [
    /\b(rateLimit\w*|rate_limit\w*|RateLimit\w*|ratelimit\w*|express-rate-limit|rate-limiter-flexible|slowDown|slow_down|throttle\w*|Throttle\w*|@Throttle|ThrottlerGuard|limiter|Bottleneck|leakyBucket|tokenBucket|TooManyRequests|too_many_requests|TOO_MANY_REQUESTS)\b|\b(?:status|statusCode|code|HTTP_429\w*)\b[^\n]{0,12}\b429\b|\b429\b[^\n]{0,12}\b(?:TooManyRequests|Too Many Requests)\b/,
  ],
};

const FLOOR: Record<MarkerLens, MarkerVocabulary> = { auth: AUTH_FLOOR, throttle: THROTTLE_FLOOR };

/** Is a pack's stack among the detected ones? A language pack (no framework, no library) always is. */
const packActive = (p: Pack, detected: ReadonlySet<string>): boolean =>
  (!p.framework && !p.library) || detected.has(p.framework ?? "") || detected.has(p.library ?? "");

/**
 * The marker for a lens: the floor, every pack's `global` names, and the
 * `detected` names of the packs whose framework or library is in `detected`.
 * Without `detected` it is the vocabulary every repository gets.
 */
export function markerFor(lens: MarkerLens, detected: Iterable<string> = [], packs: readonly Pack[] = PACKS): RegExp {
  const on = new Set(detected);
  const parts: MarkerVocabulary[] = [FLOOR[lens]];
  for (const p of packs) {
    const g = p.markers?.global?.[lens];
    if (g) parts.push(g);
  }
  for (const p of packs) {
    const d = p.markers?.detected?.[lens];
    if (d && packActive(p, on)) parts.push(d);
  }
  const words = parts.flatMap((v) => v.words ?? []);
  const annotations = parts.flatMap((v) => v.annotations ?? []);
  const patterns = parts.flatMap((v) => v.patterns ?? []);
  const alts: string[] = [];
  if (words.length) alts.push(`\\b(${words.join("|")})\\b`);
  // Annotations sit outside the leading `\b`: `\b` before `@` needs a word
  // character on its left, and an annotation is preceded by indentation.
  if (annotations.length) alts.push(`(?<![\\w@])@(?:${annotations.join("|")})\\b`);
  for (const re of patterns) alts.push(re.source);
  return new RegExp(alts.join("|"));
}

/** The stack ids a manifest's `frameworks` names — what `markerFor` reads as detected. */
export function detectedIds(stack: readonly { id: string }[] | undefined): string[] {
  return (stack ?? []).map((f) => f.id);
}
