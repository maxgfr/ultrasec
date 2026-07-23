// Zero-dep secret/PII detection + redaction for raw log text. Self-contained on
// purpose (no imports from tools/ — that half targets source-code scanners with
// a different trust model) so it can be reused unmodified by a later
// static-hygiene task. This task uses `redact()` for evidence sanitization only;
// turning a hit into its own leak Finding is a follow-up.

export interface SecretPattern {
  kind: string;
  re: RegExp;
}

// Every pattern carries the `g` flag: `String.replace` resets a global regex's
// `lastIndex` to 0 before it runs (per spec), so sharing these RegExp objects
// across many `redact()` calls is safe — no cross-call state leaks.
export const SECRET_PATTERNS: SecretPattern[] = [
  { kind: "aws-access-key", re: /AKIA[0-9A-Z]{16}/g },
  { kind: "private-key", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g },
  { kind: "jwt", re: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}/g },
  { kind: "query-secret", re: /[?&](?:password|passwd|pwd|secret|api[_-]?key|token|access[_-]?token)=[^&\s"]+/gi },
  { kind: "auth-header", re: /Authorization:\s*(?:Bearer|Basic)\s+\S+/gi },
  { kind: "slack-token", re: /xox[baprs]-[0-9A-Za-z-]{10,}/g },
  { kind: "google-api-key", re: /AIza[0-9A-Za-z_-]{35}/g },
];

export const PII_PATTERNS: SecretPattern[] = [
  { kind: "email", re: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g },
  // Credit-card CANDIDATE — gated by luhn() below (reject non-Luhn) so a plain
  // 13-16 digit run (an order id, a phone number) isn't flagged as a card.
  { kind: "credit-card", re: /\b(?:\d[ -]?){13,16}\b/g },
];

/** Luhn checksum over a digit string (non-digits already stripped by the caller). */
export function luhn(digits: string): boolean {
  const clean = digits.replace(/\D/g, "");
  if (clean.length < 13 || clean.length > 19) return false;
  let sum = 0;
  let double = false;
  for (let i = clean.length - 1; i >= 0; i--) {
    let n = Number(clean[i]);
    if (double) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    double = !double;
  }
  return sum % 10 === 0;
}

export interface RedactResult {
  redacted: string;
  hits: { kind: string }[];
}

// Cap on embedded raw/redacted evidence text kept in a finding's message —
// shared between the log analyzer (`analyze.ts`) and the static
// logging-hygiene pass (`hygiene.ts`) so a single line's evidence text has
// one truncation policy across the whole logs/ subsystem, not two that can
// drift apart.
export const EVIDENCE_MAX = 200;

/** Truncate `s` to `EVIDENCE_MAX` characters for embedding in a finding's
 *  message — never returns a longer string, no-ops on shorter ones. */
export function truncateEvidence(s: string): string {
  return s.length > EVIDENCE_MAX ? s.slice(0, EVIDENCE_MAX) : s;
}

/**
 * Replace every secret/PII match with `‹REDACTED:<kind>›`. Idempotent (running
 * it again on its own output finds nothing new — the placeholder text matches
 * none of the patterns) and never returns the matched value anywhere, including
 * in `hits` (kind only).
 */
export function redact(line: string): RedactResult {
  const hits: { kind: string }[] = [];
  let redacted = line;

  for (const p of SECRET_PATTERNS) {
    redacted = redacted.replace(p.re, () => {
      hits.push({ kind: p.kind });
      return `‹REDACTED:${p.kind}›`;
    });
  }
  for (const p of PII_PATTERNS) {
    if (p.kind === "credit-card") {
      redacted = redacted.replace(p.re, (m) => {
        if (!luhn(m)) return m; // not a valid card number — leave it alone
        hits.push({ kind: p.kind });
        return `‹REDACTED:${p.kind}›`;
      });
      continue;
    }
    redacted = redacted.replace(p.re, () => {
      hits.push({ kind: p.kind });
      return `‹REDACTED:${p.kind}›`;
    });
  }

  return { redacted, hits };
}
