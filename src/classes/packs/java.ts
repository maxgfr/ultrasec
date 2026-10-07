import type { Pack, QueryIdiom } from "../types.js";
import { EXPORT_PATH, FLAG_NAME, MENTIONS_CSV, NEUTRALIZES_FORMULA_ANY, SETS_SECURITY_HEADER } from "./shared.js";

// Java (and Kotlin where the idiom reads the same): the language idioms, then
// Spring Boot.

const JVM = ["java", "kotlin"];

const SECRET = String.raw`"[A-Z0-9_]*(?:TOKEN|SECRET|KEY|PASSWORD)"`;
/** A field/variable named for a shared credential (`apiKey`, `webhookSecret`). */
const SECRET_FIELD = String.raw`\w*(?:apiKey|ApiKey|API_KEY|sharedSecret|SharedSecret|webhookSecret|WebhookSecret|clientSecret|ClientSecret|apiToken|ApiToken)\w*`;

export const JAVA_PACK: Pack = {
  id: "java",
  ecosystem: "java",
  classes: {
    "timing-unsafe-secret-compare": {
      rules: [
        {
          id: "equals-secret",
          kind: "line",
          languages: JVM,
          match: new RegExp(
            `\\.equals\\(\\s*(?:System\\.getenv\\(\\s*${SECRET}\\s*\\)|${SECRET_FIELD})\\s*\\)|(?:System\\.getenv\\(\\s*${SECRET}\\s*\\)|\\b${SECRET_FIELD})\\s*\\.equals\\(|getHeader\\(\\s*"(?:X-Api-Key|X-API-Key|Authorization|X-Webhook-Secret)"\\s*\\)\\s*\\.equals\\(`,
          ),
          unless: /MessageDigest\.isEqual|constantTime/i,
          note: "A credential is checked with `String.equals`, which returns at the first differing character, so response time leaks how much of a guess is right. Compare digests with `MessageDigest.isEqual`.",
        },
      ],
    },
    "csv-formula-injection": {
      rules: [
        {
          id: "writer",
          kind: "file",
          languages: JVM,
          gate: [MENTIONS_CSV],
          anchor: /String\.join\(\s*"[,;]"|\.printRecord\s*\(|\.writeNext\s*\(/,
          pick: "last",
          unless: NEUTRALIZES_FORMULA_ANY,
          note: "A CSV is written (`String.join`, Commons CSV `printRecord`, OpenCSV `writeNext`) and nothing neutralizes a cell that starts with `=`, `+`, `-`, `@`, a tab or a carriage return. Opened in a spreadsheet such a cell is a formula. Prefix those cells with `'`.",
        },
      ],
    },
    "env-bool-coercion": {
      rules: [
        {
          id: "getenv-not-null",
          kind: "line",
          languages: JVM,
          match: new RegExp(`(?:boolean|Boolean|var|val)\\s+${FLAG_NAME}\\s*(?::\\s*Boolean\\s*)?=\\s*System\\.getenv\\(\\s*"[^"]+"\\s*\\)\\s*!=\\s*null`, "i"),
          note: 'The flag is "the variable is set": X=false and X=0 turn it ON. Parse the value — `Boolean.parseBoolean(System.getenv("X"))` — or bind it with Spring\'s typed `@Value`.',
        },
      ],
    },
    "session-cookie-chunks-on-logout": {
      notApplicable:
        "Java servlet containers keep the session server-side behind a single JSESSIONID-style cookie; there are no numbered chunks for a logout to miss.",
    },
  },
};

// ── Spring Boot ─────────────────────────────────────────────────────────────
// Spring Security writes Cache-Control, X-Content-Type-Options, HSTS (over
// HTTPS), X-Frame-Options: DENY and X-XSS-Protection: 0 by default — but only
// when Spring Security is on the classpath; plain Spring MVC sends none.
// Source: https://docs.spring.io/spring-security/reference/servlet/exploits/headers.html
const SPRING_QUERIES: QueryIdiom[] = [
  // A repository `findAll()` with no Pageable/Sort argument loads the table.
  { start: /\b\w*(?:Repository|Repo|repository|repo)\s*\.\s*findAll\s*\(\s*\)/, bounded: /(?!)/ },
  // JdbcTemplate with a literal SELECT.
  { start: /\.\s*query(?:ForList)?\s*\(\s*"\s*SELECT\b/i, bounded: /\bLIMIT\b|\bFETCH\s+FIRST\b/i },
];

export const SPRING_PACK: Pack = {
  id: "spring",
  ecosystem: "java",
  framework: "spring",
  testedWith: ">=2.7 <5",
  sources: ["https://docs.spring.io/spring-security/reference/servlet/exploits/headers.html"],
  classes: {
    "security-headers-absent": {
      rules: [
        {
          id: "headers-disabled",
          kind: "line",
          languages: JVM,
          match:
            /\.headers\s*\(\s*(?:\(?\s*\w+\s*\)?\s*->\s*\w+\s*\.\s*disable\s*\(\s*\)|AbstractHttpConfigurer::disable)\s*\)|\.headers\s*\(\s*\)\s*\.\s*disable\s*\(|\.defaultsDisabled\s*\(/,
          note: "Spring Security's default response headers (X-Content-Type-Options, X-Frame-Options: DENY, HSTS, Cache-Control) are switched off here. Keep the defaults (`headers(withDefaults())`) and only override the header you need to.",
        },
        {
          id: "no-spring-security",
          kind: "absent",
          languages: JVM,
          requiresFramework: "spring",
          anchor: /@SpringBootApplication\b/,
          presentInTree: {
            re: new RegExp(
              `spring-boot-starter-security|spring-security-(?:web|config)|SecurityFilterChain|addHeaderWriter|${SETS_SECURITY_HEADER.source}`,
              "i",
            ),
            scope: "package",
            files: /(?:^|\/)(?:pom\.xml|build\.gradle(?:\.kts)?)$|\.(?:java|kt)$/,
          },
          note: "This Spring Boot application has no Spring Security on its build and sets no security header itself, so responses carry none: Spring MVC writes no CSP, HSTS, X-Frame-Options or X-Content-Type-Options. Add spring-boot-starter-security (its defaults set most of them) or a header filter — unless the proxy in front sets them.",
        },
      ],
    },
    "unbounded-public-export": {
      rules: [
        {
          id: "controller",
          kind: "route-query",
          languages: JVM,
          exportPath: EXPORT_PATH,
          routeDecl: /@(?:Get|Request|Post)Mapping\s*\(\s*(?:value\s*=\s*|path\s*=\s*)?\{?\s*"([^"]+)"/,
          queries: SPRING_QUERIES,
          statement: "balanced",
        },
      ],
    },
  },
};

export const JAVA_PACKS: Pack[] = [JAVA_PACK, SPRING_PACK];
