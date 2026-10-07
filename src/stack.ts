import type { Ecosystem } from "./classes/types.js";

// What a repository is built with — ONE table, as data.
//
// Two passes used to answer this question separately and disagreed: the context
// brief (`context`) matched regexes against raw manifest text, and the
// weakness-class matrix (`frameworks.ts`) read the manifests structurally, with
// versions. A Phoenix or Rust repo had a stack in the brief and none in the
// matrix, so its classes were not even listed as unhunted. Both now read this
// table through `detectFrameworks`; adding a stack is adding a row.
//
// A `web` entry is an HTTP framework: a column of the weakness-class matrix,
// hunted class by class when no pack covers it. A `library` entry is named in
// the context brief, and attaches to the framework columns of its package when
// a library pack (`Pack.library`) or a catalog idiom is written against it —
// which is how a library's own version range (`testedWith`) can degrade a cell.

/** The registries whose manifests are read (see `MANIFESTS` in frameworks.ts). */
export type Registry = "npm" | "pypi" | "maven" | "go" | "gem" | "composer" | "hex" | "cargo" | "nuget" | "deno";

export interface StackEntry {
  /** Stable id: what packs, catalog idioms and hunt ids name. */
  id: string;
  title: string;
  ecosystem: Ecosystem;
  kind: "web" | "library";
  /**
   * Dependency names that mean "this package uses it", per registry, in lower
   * case (PyPI names normalized to `-`). A trailing `*` matches a prefix.
   */
  deps: Partial<Record<Registry, readonly string[]>>;
  /** A framework with no manifest entry: detected from an import in the
   *  package's own code, versioned by the toolchain the manifest declares. */
  codeImport?: { registry: Registry; extension: string; re: RegExp };
  /** The name the context brief shows, when it is not the id. */
  label?: string;
  /** The languages its application code is written in, when not its ecosystem's. */
  languages?: readonly string[];
}

/** The languages (`src/lang.ts` ids) each ecosystem's application code is written in. */
export const ECOSYSTEM_LANGUAGES: Record<Ecosystem, readonly string[]> = {
  node: ["javascript"],
  deno: ["javascript"],
  python: ["python"],
  java: ["java", "kotlin", "scala"],
  go: ["go"],
  ruby: ["ruby"],
  php: ["php"],
  elixir: ["elixir"],
  rust: ["rust"],
  dotnet: ["csharp"],
};

const web = (id: string, title: string, ecosystem: Ecosystem, deps: StackEntry["deps"], extra: Partial<StackEntry> = {}): StackEntry => ({
  id,
  title,
  ecosystem,
  kind: "web",
  deps,
  ...extra,
});
const lib = (id: string, title: string, ecosystem: Ecosystem, deps: StackEntry["deps"], extra: Partial<StackEntry> = {}): StackEntry => ({
  id,
  title,
  ecosystem,
  kind: "library",
  deps,
  ...extra,
});

export const STACK: readonly StackEntry[] = [
  // ── Node / Deno ───────────────────────────────────────────────────────────
  web("nextjs", "Next.js", "node", { npm: ["next"] }, { label: "next.js" }),
  web("express", "Express", "node", { npm: ["express"] }),
  web("nestjs", "NestJS", "node", { npm: ["@nestjs/core"] }),
  web("fastify", "Fastify", "node", { npm: ["fastify"] }),
  web("koa", "Koa", "node", { npm: ["koa"] }),
  web("hono", "Hono", "node", { npm: ["hono"], deno: ["hono", "@hono/hono"] }),
  web("elysia", "Elysia", "node", { npm: ["elysia"] }),
  web("hapi", "hapi", "node", { npm: ["@hapi/hapi", "hapi"] }),
  web("restify", "restify", "node", { npm: ["restify"] }),
  web("sails", "Sails", "node", { npm: ["sails"] }),
  web("nuxt", "Nuxt", "node", { npm: ["nuxt"] }),
  web("sveltekit", "SvelteKit", "node", { npm: ["@sveltejs/kit"] }),
  web("fresh", "Fresh", "deno", { deno: ["fresh", "@fresh/core"] }),
  web("oak", "Oak", "deno", { deno: ["oak", "@oak/oak"] }),
  lib("next-auth", "NextAuth.js", "node", { npm: ["next-auth"] }),
  lib("trpc", "tRPC", "node", { npm: ["@trpc/server"] }),
  lib("drizzle", "Drizzle ORM", "node", { npm: ["drizzle-orm"] }),
  lib("react", "React", "node", { npm: ["react"] }),
  lib("vue", "Vue", "node", { npm: ["vue"] }),
  lib("angular", "Angular", "node", { npm: ["@angular/core"] }),
  lib("svelte", "Svelte", "node", { npm: ["svelte"] }),
  lib("apollo", "Apollo Server", "node", { npm: ["apollo-server", "@apollo/server"] }),
  lib("graphql", "GraphQL.js", "node", { npm: ["graphql"] }),
  lib("socket.io", "Socket.IO", "node", { npm: ["socket.io"] }),
  lib("mongoose", "Mongoose", "node", { npm: ["mongoose"] }),
  lib("sequelize", "Sequelize", "node", { npm: ["sequelize"] }),
  lib("prisma", "Prisma", "node", { npm: ["prisma", "@prisma/client"] }),
  lib("knex", "Knex", "node", { npm: ["knex"] }),
  lib("typeorm", "TypeORM", "node", { npm: ["typeorm"] }),
  lib("passport", "Passport", "node", { npm: ["passport"] }),
  lib("jwt", "jsonwebtoken", "node", { npm: ["jsonwebtoken"] }),

  // ── Python ────────────────────────────────────────────────────────────────
  web("django", "Django", "python", { pypi: ["django"] }),
  web("flask", "Flask", "python", { pypi: ["flask"] }),
  web("fastapi", "FastAPI", "python", { pypi: ["fastapi"] }),
  web("starlette", "Starlette", "python", { pypi: ["starlette"] }),
  web("sanic", "Sanic", "python", { pypi: ["sanic"] }),
  web("tornado", "Tornado", "python", { pypi: ["tornado"] }),
  web("aiohttp", "aiohttp", "python", { pypi: ["aiohttp"] }),
  web("bottle", "Bottle", "python", { pypi: ["bottle"] }),
  web("pyramid", "Pyramid", "python", { pypi: ["pyramid"] }),
  web("quart", "Quart", "python", { pypi: ["quart"] }),
  lib("sqlalchemy", "SQLAlchemy", "python", { pypi: ["sqlalchemy"] }),

  // ── JVM ───────────────────────────────────────────────────────────────────
  web("spring", "Spring Boot", "java", {
    maven: ["spring-boot-starter-web", "spring-boot-starter-webflux", "spring-webmvc", "spring-webflux"],
  }),
  web("quarkus", "Quarkus", "java", { maven: ["quarkus-rest", "quarkus-resteasy", "quarkus-resteasy-reactive"] }),
  web("micronaut", "Micronaut", "java", { maven: ["micronaut-http-server-netty"] }),
  web("jersey", "Jersey", "java", { maven: ["jersey-server", "jersey-container-*"] }),
  web("ktor", "Ktor", "java", { maven: ["ktor-server-core", "ktor-server-core-jvm", "ktor-server-netty", "ktor-server-netty-jvm"] }, { languages: ["kotlin"] }),

  // ── Go ────────────────────────────────────────────────────────────────────
  web("gin", "Gin", "go", { go: ["github.com/gin-gonic/gin"] }),
  web("echo", "Echo", "go", { go: ["github.com/labstack/echo/v4", "github.com/labstack/echo"] }),
  web("fiber", "Fiber", "go", { go: ["github.com/gofiber/fiber/v2", "github.com/gofiber/fiber/v3"] }),
  web("chi", "chi", "go", { go: ["github.com/go-chi/chi/v5", "github.com/go-chi/chi"] }),
  web("gorilla-mux", "gorilla/mux", "go", { go: ["github.com/gorilla/mux"] }, { label: "gorilla/mux" }),
  web("net-http", "Go net/http", "go", {}, { codeImport: { registry: "go", extension: ".go", re: /^\s*(?:import\s+)?(?:\w+\s+)?"net\/http"\s*$/ } }),
  lib("gorm", "GORM", "go", { go: ["gorm.io/gorm"] }),

  // ── Ruby ──────────────────────────────────────────────────────────────────
  web("rails", "Ruby on Rails", "ruby", { gem: ["rails"] }),
  web("sinatra", "Sinatra", "ruby", { gem: ["sinatra"] }),
  web("hanami", "Hanami", "ruby", { gem: ["hanami"] }),
  lib("sequel", "Sequel", "ruby", { gem: ["sequel"] }),

  // ── PHP ───────────────────────────────────────────────────────────────────
  web("laravel", "Laravel", "php", { composer: ["laravel/framework"] }),
  web("symfony", "Symfony", "php", { composer: ["symfony/framework-bundle"] }),
  web("slim", "Slim", "php", { composer: ["slim/slim"] }),

  // ── Elixir ────────────────────────────────────────────────────────────────
  web("phoenix", "Phoenix", "elixir", { hex: ["phoenix"] }),
  lib("plug", "Plug", "elixir", { hex: ["plug", "plug_cowboy"] }),
  lib("ecto", "Ecto", "elixir", { hex: ["ecto", "ecto_sql"] }),

  // ── Rust ──────────────────────────────────────────────────────────────────
  web("actix-web", "actix-web", "rust", { cargo: ["actix-web"] }),
  web("axum", "axum", "rust", { cargo: ["axum"] }),
  web("rocket", "Rocket", "rust", { cargo: ["rocket"] }),
  web("warp", "warp", "rust", { cargo: ["warp"] }),
  web("tide", "tide", "rust", { cargo: ["tide"] }),
  lib("diesel", "Diesel", "rust", { cargo: ["diesel"] }),
  lib("sqlx", "SQLx", "rust", { cargo: ["sqlx"] }),

  // ── .NET ──────────────────────────────────────────────────────────────────
  // `Microsoft.NET.Sdk.Web` is the project SDK every ASP.NET Core app declares;
  // the reader surfaces it as a dependency so it matches like any other.
  web("aspnetcore", "ASP.NET Core", "dotnet", { nuget: ["microsoft.net.sdk.web", "microsoft.aspnetcore.*"] }),
];

/** The languages an entry's application code is written in. */
export function languagesOf(entry: { ecosystem: Ecosystem; languages?: readonly string[] }): readonly string[] {
  return entry.languages ?? ECOSYSTEM_LANGUAGES[entry.ecosystem];
}

/** The ecosystem a language's code belongs to (first match), for code-only evidence. */
export function ecosystemOfLanguage(lang: string): Ecosystem | undefined {
  return (Object.entries(ECOSYSTEM_LANGUAGES) as [Ecosystem, readonly string[]][]).find(([eco, langs]) => eco !== "deno" && langs.includes(lang))?.[0];
}

// ── A web framework the table does not know ─────────────────────────────────
//
// A package whose code declares HTTP routes is a web application whatever the
// table says, and saying nothing about it is the worst way to be wrong: its
// classes would not even be listed as unhunted. So a package with no known web
// framework (in it or in a package above it) gets an `unknown` column — every
// class hunted — when its own code carries route declarations.
//
// The heuristic is deliberately prudent, because every column costs one hunt
// per class:
//   • a route declaration is a verb + an ABSOLUTE path literal + a handler
//     (a function literal, a controller reference), never a bare call — so an
//     HTTP CLIENT (`axios.get("/api/users", config)`) is not a route; a
//     request handler the walk already counts as an HTTP entry point (the
//     catalog's request inputs and route conventions) is evidence too;
//   • two such lines in the package, or one when the package also declares a
//     dependency whose name says it serves HTTP (`@acme/http-server`) and that
//     no table row explains;
//   • test files never count.

/** What declares an HTTP route, per language (`src/lang.ts` ids). */
export const ROUTE_EVIDENCE: Record<string, readonly RegExp[]> = {
  javascript: [
    /\b(?!(?:axios|fetch|http|https|client|request|got|ky|superagent|instance|\$http)\b)[A-Za-z_$][\w$]*\s*\.\s*(?:get|post|put|patch|delete|all|route)\s*\(\s*["'`]\/[^"'`]*["'`]\s*,\s*(?:async\b|function\b|\([^)]*\)\s*(?::[^=]+)?=>|[A-Za-z_$][\w$]*\s*=>)/,
    /\bmethod\s*:\s*["'](?:GET|POST|PUT|PATCH|DELETE)["']\s*,\s*path\s*:\s*["']\//i,
  ],
  python: [/^\s*@\w+(?:\.\w+)*\.(?:get|post|put|patch|delete|route|api_route|websocket)\s*\(\s*["']\//],
  ruby: [/^\s*(?:get|post|put|patch|delete)\s+["']\/[^"']*["']\s*(?:,|do\b|\{)/],
  // A router line, or a controller action — `def index(conn, params)` IS an endpoint.
  elixir: [/^\s*(?:get|post|put|patch|delete)\s+"\/[^"]*"\s*,\s*[A-Z]\w*/, /^\s*def\s+\w+\s*\(\s*conn\s*,\s*(?:_?\w*params\b|%\{)/],
  php: [/(?:->|::)\s*(?:get|post|put|patch|delete|any|map)\s*\(\s*["']\/[^"']*["']\s*,\s*(?:function\b|fn\b|\[|[A-Z]\w*::class)/],
  go: [/\.\s*(?:HandleFunc|Handle|GET|POST|PUT|PATCH|DELETE|Get|Post|Put|Patch|Delete)\s*\(\s*"\/[^"]*"\s*,/],
  rust: [/#\[\s*(?:get|post|put|patch|delete)\s*\(\s*"\//, /\.route\s*\(\s*"\/[^"]*"\s*,/],
  csharp: [/\.Map(?:Get|Post|Put|Patch|Delete)\s*\(\s*"\//, /\[Http(?:Get|Post|Put|Patch|Delete)\s*\(\s*"/],
  java: [/@(?:Get|Post|Put|Delete|Patch|Request)Mapping\b/, /@(?:GET|POST|PUT|DELETE|PATCH)\b/, /@Path\s*\(\s*"\//],
  kotlin: [/@(?:Get|Post|Put|Delete|Patch|Request)Mapping\b/, /^\s*(?:get|post|put|patch|delete)\s*\(\s*"\/[^"]*"\s*\)\s*\{/],
  scala: [/@(?:Get|Post|Put|Delete|Patch|Request)Mapping\b/, /@Path\s*\(\s*"\//],
};

/** A dependency whose name says it serves HTTP. */
export const HTTP_DEPENDENCY = /(?:^|[/@._-])(?:http|https|web|rest|router|routing|server|mvc)(?:[/._-]|$)/i;

/** …unless the name says it is a client, a type package, or tooling. */
export const NOT_A_SERVER =
  /^@types\/|(?:^|[/@._-])(?:client|fetch|axios|proxy|errors?|status(?:es)?|vitals|tests?|testing|mocks?|types?|parser|cache|cookies?|signature|socket|websockets?|webpack|devserver|dev-server)(?:[/._-]|$)/i;
