import type { Pack, QueryIdiom } from "../types.js";
import { EXPORT_PATH, MENTIONS_CSV, NEUTRALIZES_FORMULA_ANY, XFF, XFF_LOOKBACK } from "./shared.js";

// Ruby: the language idioms, then Rails.

const RB = ["ruby"];

const SECRET = String.raw`["'][A-Z][A-Z0-9_]*(?:TOKEN|SECRET|KEY|PASSWORD)["']`;
const ENV_SECRET = String.raw`ENV(?:\[\s*${SECRET}\s*\]|\.fetch\(\s*${SECRET}\s*\))`;

export const RUBY_PACK: Pack = {
  id: "ruby",
  ecosystem: "ruby",
  classes: {
    "timing-unsafe-secret-compare": {
      rules: [
        {
          id: "env-secret",
          kind: "line",
          languages: RB,
          match: new RegExp(
            `(?:==|!=)\\s*(?:${ENV_SECRET}|Rails\\.application\\.credentials\\.\\w*(?:token|secret|key)\\w*)|(?:${ENV_SECRET}|request\\.headers\\[\\s*["'](?:X-Api-Key|X-API-Key|Authorization|X-Webhook-Secret)["']\\s*\\])\\s*(?:==|!=)(?!\\s*(?:nil|""|''))`,
          ),
          unless: /secure_compare|fixed_length_secure_compare/,
          note: "A credential is compared with `==`, which returns at the first differing byte, so response time leaks how much of a guess is right. Use `ActiveSupport::SecurityUtils.secure_compare` (or `Rack::Utils.secure_compare`).",
        },
      ],
    },
    "csv-formula-injection": {
      rules: [
        {
          id: "writer",
          kind: "file",
          languages: RB,
          gate: [MENTIONS_CSV],
          anchor: /\bCSV\.(?:generate|open)\b|\bcsv\s*<<|\.to_csv\b/,
          pick: "last",
          unless: NEUTRALIZES_FORMULA_ANY,
          note: "A CSV is written (`CSV.generate`, `csv << row`, `to_csv`) and nothing neutralizes a cell that starts with `=`, `+`, `-`, `@`, a tab or a carriage return. Opened in a spreadsheet such a cell is a formula. Prefix those cells with `'`.",
        },
      ],
    },
    "client-ip-first-xff": {
      rules: [
        {
          id: "split-first",
          kind: "line",
          languages: RB,
          match: /\.split\(\s*["']\s*,\s*["']\s*\)\s*\.first\b/,
          context: { re: XFF, before: XFF_LOOKBACK },
          emit: "webconfig/xff-first-hop",
        },
      ],
    },
    "env-bool-coercion": {
      rules: [
        {
          id: "env-truthiness",
          kind: "line",
          languages: RB,
          match: /!!\s*ENV\[|ENV\[\s*["'][^"']+["']\s*\]\.present\?|ENV\.fetch\(\s*["'][^"']+["']\s*,\s*(?:true|false)\s*\)/,
          note: 'Every environment value is a String and every String is truthy: X=false keeps the flag ON. Cast it — `ActiveModel::Type::Boolean.new.cast(ENV["X"])` — or compare against "true".',
        },
      ],
    },
    "session-cookie-chunks-on-logout": {
      notApplicable:
        "Rails' cookie store keeps the session in one cookie and raises CookieOverflow past 4 KB rather than splitting it; there are no chunks for a logout to miss.",
    },
  },
};

// ── Rails ───────────────────────────────────────────────────────────────────
// Rails sends X-Frame-Options: SAMEORIGIN, X-XSS-Protection: 0,
// X-Content-Type-Options: nosniff, X-Permitted-Cross-Domain-Policies: none and
// Referrer-Policy: strict-origin-when-cross-origin by default
// (config.action_dispatch.default_headers). CSP is NOT enabled by default: it
// is configured in config/initializers/content_security_policy.rb.
// Source: https://guides.rubyonrails.org/security.html#default-headers
const RAILS_QUERIES: QueryIdiom[] = [
  {
    start: /\b[A-Z]\w*(?:::[A-Z]\w*)*\.(?:all|where|order|includes|joins|select|eager_load)\b/,
    bounded: /\.(?:limit|page|paginate|per|find_each|find_in_batches|in_batches|first|last|take|find_by|find|count|exists\?|pluck_first)\b/,
  },
];

export const RAILS_PACK: Pack = {
  id: "rails",
  ecosystem: "ruby",
  framework: "rails",
  testedWith: ">=6 <9",
  sources: ["https://guides.rubyonrails.org/security.html"],
  classes: {
    "security-headers-absent": {
      rules: [
        {
          id: "default-headers-cleared",
          kind: "line",
          languages: RB,
          match: /\bdefault_headers\s*=\s*\{\s*\}|\bdefault_headers\.clear\b/,
          note: "Rails' default security headers (X-Frame-Options, X-Content-Type-Options, Referrer-Policy) are wiped here. Keep the defaults and override only the header you mean to change.",
        },
        {
          id: "no-csp",
          kind: "absent",
          languages: RB,
          anchor: /<\s*Rails::Application\b/,
          presentInTree: { re: /\bcontent_security_policy\b/, scope: "package", languages: RB },
          note: "Rails sends X-Frame-Options, X-Content-Type-Options and Referrer-Policy by default, but no Content-Security-Policy until one is configured — and the generated `config/initializers/content_security_policy.rb` is entirely commented out. Configure the policy there (a nonce for inline scripts) — unless the proxy in front sets one.",
        },
      ],
    },
    "unbounded-public-export": {
      rules: [
        {
          id: "controller",
          kind: "route-query",
          languages: RB,
          files: /_controller\.rb$/,
          routeFile: /_controller\.rb$/,
          exportPath: EXPORT_PATH,
          routeDecl: /^\s*def\s+(\w+)/,
          queries: RAILS_QUERIES,
          statement: "balanced",
        },
      ],
    },
  },
};

export const RUBY_PACKS: Pack[] = [RUBY_PACK, RAILS_PACK];
