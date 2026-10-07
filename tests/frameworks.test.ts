import { describe, it, expect } from "vitest";
import { dirname, join } from "node:path";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { detectFrameworks, floorOf, inferUnknownFrameworks, satisfies, stackLabels, webFrameworks } from "../src/frameworks.js";

// Framework detection is what decides whether a weakness-class pack ran inside
// the version range it was validated against. A wrong version there is a
// silent coverage claim, so every ecosystem's manifest + lockfile shape is
// pinned here, in a monorepo where each package must keep its own answer.

const MONOREPO = join(import.meta.dirname, "fixtures", "frameworks-monorepo");

describe("detectFrameworks", () => {
  const stack = detectFrameworks(MONOREPO);
  const found = webFrameworks(stack);
  const by = (id: string) => stack.filter((f) => f.id === id);

  it("finds one framework per package, with the line that declares it", () => {
    expect(found.map((f) => `${f.dir}:${f.id}`)).toEqual([
      "apps/api:express",
      "apps/hapi:hapi",
      "apps/web:nextjs",
      "services/deno:fresh",
      "services/dotnet:aspnetcore",
      "services/flask:flask",
      "services/gin:gin",
      "services/gin:net-http",
      "services/java:spring",
      "services/kotlin:spring",
      "services/ktor:ktor",
      "services/laravel:laravel",
      "services/mvc:spring",
      "services/phoenix:phoenix",
      "services/py:django",
      "services/rails:rails",
      "services/rust:axum",
      "services/sanic:sanic",
      "services/sanic:starlette",
    ]);
    expect(by("nextjs")[0]!.evidence).toBe("apps/web/package.json:5");
    expect(by("django")[0]!.evidence).toBe("services/py/requirements.txt:2");
    expect(by("net-http")[0]!.evidence).toBe("services/gin/main.go:4");
  });

  it("reads the installed version from the lockfile when there is one", () => {
    expect(by("nextjs")[0]).toMatchObject({ version: "15.1.6", versionSource: "lockfile" });
    expect(by("flask")[0]).toMatchObject({ version: "3.0.3", versionSource: "lockfile" });
    expect(by("rails")[0]).toMatchObject({ version: "7.1.3", versionSource: "lockfile" });
    expect(by("laravel")[0]).toMatchObject({ version: "11.9.0", versionSource: "lockfile" });
    expect(by("gin")[0]).toMatchObject({ version: "1.9.1", versionSource: "lockfile" });
  });

  it("falls back to the floor of the declared range, and says so", () => {
    expect(by("express")[0]).toMatchObject({ version: "4.21.2", versionSource: "declared" });
    expect(by("django")[0]).toMatchObject({ version: "4.2.7", versionSource: "declared" });
    expect(found.find((f) => f.dir === "services/java")).toMatchObject({ version: "3.2.5" });
    expect(found.find((f) => f.dir === "services/kotlin")).toMatchObject({ version: "3.3.0" });
  });

  it("versions `spring` as Spring Boot: plain Spring MVC gets no version, not Spring Framework's", () => {
    const mvc = found.find((f) => f.dir === "services/mvc")!;
    expect(mvc.version).toBeUndefined();
    expect(mvc.evidence).toBe("services/mvc/pom.xml:5");
  });

  it("reads the ecosystems the context brief named but the matrix never saw, with their versions", () => {
    expect(by("phoenix")[0]).toMatchObject({ ecosystem: "elixir", version: "1.7.14", versionSource: "lockfile", evidence: "services/phoenix/mix.exs:6" });
    expect(by("axum")[0]).toMatchObject({ ecosystem: "rust", version: "0.7.5", versionSource: "lockfile", evidence: "services/rust/Cargo.toml:6" });
    expect(by("aspnetcore")[0]).toMatchObject({ ecosystem: "dotnet", version: "8.0", versionSource: "toolchain", evidence: "services/dotnet/Api.csproj:1" });
    expect(by("fresh")[0]).toMatchObject({ ecosystem: "deno", version: "1.6.8", versionSource: "declared", evidence: "services/deno/deno.json:3" });
    expect(by("ktor")[0]).toMatchObject({ ecosystem: "java", languages: ["kotlin"], version: "2.3.12", versionSource: "declared" });
    expect(by("hapi")[0]).toMatchObject({ ecosystem: "node", version: "21.3.0", versionSource: "declared" });
    expect(by("sanic")[0]).toMatchObject({ ecosystem: "python", version: "23.12.1" });
  });

  it("reports libraries as libraries, from the same table", () => {
    expect(by("react")[0]).toMatchObject({ kind: "library", dir: "apps/web", version: "19.0.0" });
    expect(by("plug")[0]).toMatchObject({ kind: "library", dir: "services/phoenix", version: "2.7.1" });
    expect(found.some((f) => f.kind === "library")).toBe(false);
  });

  it("names the stack for the context brief with its labels", () => {
    const labels = stackLabels(stack);
    expect(labels).toContain("next.js");
    expect(labels).toContain("phoenix");
    expect(labels).toContain("plug");
    expect(labels).not.toContain("nextjs");
  });

  it("dates Go's net/http by the toolchain the module declares", () => {
    expect(by("net-http")[0]).toMatchObject({ version: "1.22", versionSource: "toolchain" });
  });

  it("honours the prune predicate", () => {
    expect(webFrameworks(detectFrameworks(MONOREPO, (rel) => rel.startsWith("services/"))).map((f) => f.id)).toEqual(["express", "hapi", "nextjs"]);
  });
});

describe("version ranges", () => {
  it("satisfies space-separated comparators and || alternatives", () => {
    expect(satisfies("16.3.3", ">=12 <17")).toBe(true);
    expect(satisfies("17.0.0", ">=12 <17")).toBe(false);
    expect(satisfies("v1.9.1", ">=1.7 <2")).toBe(true);
    expect(satisfies("3.1.0", ">=2 <3 || >=3.1")).toBe(true);
    expect(satisfies("2.5", "=2.5")).toBe(true);
  });

  it("reads the floor of a declared range", () => {
    expect(floorOf("^16.2.11")).toBe("16.2.11");
    expect(floorOf(">=4.2,<5")).toBe("4.2");
    expect(floorOf("~> 7.1.0")).toBe("7.1.0");
    expect(floorOf("*")).toBeUndefined();
  });
});

describe("inferUnknownFrameworks", () => {
  const repoWith = (files: Record<string, string>): string => {
    const repo = mkdtempSync(join(tmpdir(), "ultrasec-unknown-fw-"));
    for (const [rel, text] of Object.entries(files)) {
      mkdirSync(dirname(join(repo, rel)), { recursive: true });
      writeFileSync(join(repo, rel), text);
    }
    return repo;
  };
  const infer = (repo: string) => inferUnknownFrameworks(repo, detectFrameworks(repo));

  it("gives a package whose code declares routes an `unknown` column, grounded on its first route", () => {
    const repo = repoWith({
      "package.json": JSON.stringify({ dependencies: { "@acme/http-kit": "^2.0.0" } }, null, 2),
      "src/server.js": 'const app = require("@acme/http-kit")();\napp.get("/export", async (req, res) => res.send(await rows()));\n',
    });
    expect(infer(repo)).toEqual([
      expect.objectContaining({ id: "unknown", kind: "inferred", ecosystem: "node", dir: "", evidence: "src/server.js:2", languages: ["javascript"] }),
    ]);
    expect(infer(repo)[0]!.title).toContain("@acme/http-kit");
  });

  it("needs two route lines when no dependency says it serves HTTP", () => {
    const one = repoWith({ "main.py": '@app.get("/health")\ndef health():\n    return "ok"\n' });
    expect(infer(one)).toEqual([]);
    const two = repoWith({ "main.py": '@app.get("/health")\ndef health():\n    return "ok"\n\n@app.post("/export")\ndef export():\n    return rows()\n' });
    expect(infer(two)).toEqual([expect.objectContaining({ id: "unknown", ecosystem: "python", evidence: "main.py:1" })]);
  });

  it("does not read an HTTP client, a comment or a test as a route", () => {
    const repo = repoWith({
      "package.json": JSON.stringify({ dependencies: { axios: "1.7.0", "web-vitals": "4.0.0" } }),
      "src/api.js": 'axios.get("/api/users", config);\nhttp.post("/api/users", { name });\n// app.get("/x", (req, res) => res.end());\n',
      "src/__tests__/server.test.js": 'app.get("/x", (req, res) => res.end());\napp.post("/y", (req, res) => res.end());\n',
    });
    expect(infer(repo)).toEqual([]);
  });

  it("never infers under a package that has a known web framework", () => {
    const repo = repoWith({
      "package.json": JSON.stringify({ dependencies: { express: "4.21.2" } }),
      "routes/a.js": 'router.get("/a", (req, res) => res.end());\nrouter.post("/b", (req, res) => res.end());\n',
      "packages/x/package.json": JSON.stringify({ name: "x" }),
      "packages/x/r.js": 'router.get("/a", (req, res) => res.end());\nrouter.post("/b", (req, res) => res.end());\n',
    });
    expect(infer(repo)).toEqual([]);
  });

  it("counts the request handlers the walk already knows — a manifest-less Phoenix controller", () => {
    const repo = repoWith({
      "lib/export_controller.ex":
        'defmodule AppWeb.ExportController do\n  def index(conn, params) do\n    ip = conn.req_headers |> List.keyfind("x-forwarded-for", 0)\n    json(conn, %{ip: ip, q: params["q"]})\n  end\nend\n',
    });
    expect(infer(repo)).toEqual([
      expect.objectContaining({ id: "unknown", ecosystem: "elixir", dir: "", evidence: "lib/export_controller.ex:2", languages: ["elixir"] }),
    ]);
  });

  it("finds a Sinatra-shaped route table in a package the table does not know", () => {
    const repo = repoWith({
      Gemfile: 'gem "roda-like", "1.0"\n',
      "app.rb": 'get "/export" do\n  rows.to_json\nend\npost "/import" do\n  import!\nend\n',
    });
    expect(infer(repo)).toEqual([expect.objectContaining({ ecosystem: "ruby", evidence: "app.rb:1" })]);
  });
});
