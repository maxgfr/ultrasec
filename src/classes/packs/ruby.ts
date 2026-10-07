import type { Pack, QueryIdiom } from "../types.js";
import { COOKIE_HTTPONLY_SET, COOKIE_SECURE_SET, EXPORT_PATH, MENTIONS_CSV, NEUTRALIZES_FORMULA_ANY, XFF, XFF_LOOKBACK } from "./shared.js";

// Ruby: the language idioms, then Rails.

const RB = ["ruby"];

const SECRET = String.raw`["'][A-Z0-9_]*(?:TOKEN|SECRET|KEY|PASSWORD)["']`;
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
    "request-body-unbounded": {
      hunt: "Rack and Puma set no request-body limit and Rails parses JSON bodies whole; check what bounds them — a Rack middleware, the app server, or the proxy's client_max_body_size.",
    },
    "graphql-introspection-enabled": {
      hunt: "graphql-ruby answers introspection unless the schema calls `disable_introspection_entry_points`, and GraphiQL is a mounted engine (`GraphiQL::Rails::Engine`); check both against the production environment.",
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
    // The original web-config detector's Rails rules (raw lines: a
    // commented-out `protect_from_forgery` IS the finding).
    "csrf-protection-disabled": {
      rules: [
        { id: "protect-commented", kind: "line", languages: RB, text: "raw", match: /^\s*#\s*protect_from_forgery\b/, emit: "webconfig/csrf-disabled" },
        {
          id: "skip-verify",
          kind: "line",
          languages: RB,
          text: "raw",
          match: /\bskip_before_action\s+:verify_authenticity_token\b/,
          emit: "webconfig/csrf-disabled",
        },
        {
          id: "null-session",
          kind: "line",
          languages: RB,
          text: "raw",
          match: /\bprotect_from_forgery\s+with:\s*:null_session\b/,
          emit: "webconfig/csrf-disabled",
        },
      ],
    },
    "debug-mode-enabled": {
      rules: [{ id: "all-requests-local", kind: "line", languages: RB, text: "raw", match: /consider_all_requests_local\s*=\s*true/, emit: "webconfig/debug" }],
    },
    // A cookie written through the jar with a bare value gets neither flag;
    // the hash form is where `httponly:`/`secure:` go.
    // Source: https://api.rubyonrails.org/classes/ActionDispatch/Cookies.html
    "insecure-session-cookie": {
      rules: [
        {
          id: "cookie-jar-assign",
          kind: "call",
          languages: RB,
          call: /\bcookies(?:\.(?:signed|encrypted|permanent))*\s*\[[^\]\n]+\]\s*=(?!=)/,
          scope: "statement",
          options: { args: /\{/ },
          bare: ["webconfig/cookie-httponly", "webconfig/cookie-secure"],
          flags: [
            { emit: "webconfig/cookie-httponly", present: COOKIE_HTTPONLY_SET },
            { emit: "webconfig/cookie-secure", present: COOKIE_SECURE_SET },
          ],
        },
      ],
    },
    // Rails rejects a request whose Client-IP and X-Forwarded-For disagree;
    // switched off, `request.remote_ip` follows whichever the caller sent.
    // Source: https://guides.rubyonrails.org/configuring.html#config-action-dispatch-ip-spoofing-check
    "proxy-headers-trusted": {
      rules: [
        {
          id: "ip-spoofing-check-off",
          kind: "line",
          languages: RB,
          match: /\bip_spoofing_check\s*=\s*false\b/,
          note: "`ip_spoofing_check = false` turns off the check that makes Rails refuse a request whose Client-IP and X-Forwarded-For disagree, so `request.remote_ip` follows whatever the caller sent. Leave it on and configure `trusted_proxies` instead.",
        },
      ],
    },
  },
};

export const RUBY_PACKS: Pack[] = [RUBY_PACK, RAILS_PACK];
