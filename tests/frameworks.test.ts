import { describe, it, expect } from "vitest";
import { join } from "node:path";
import { detectFrameworks, floorOf, satisfies } from "../src/frameworks.js";

// Framework detection is what decides whether a weakness-class pack ran inside
// the version range it was validated against. A wrong version there is a
// silent coverage claim, so every ecosystem's manifest + lockfile shape is
// pinned here, in a monorepo where each package must keep its own answer.

const MONOREPO = join(import.meta.dirname, "fixtures", "frameworks-monorepo");

describe("detectFrameworks", () => {
  const found = detectFrameworks(MONOREPO);
  const by = (id: string) => found.filter((f) => f.id === id);

  it("finds one framework per package, with the line that declares it", () => {
    expect(found.map((f) => `${f.dir}:${f.id}`)).toEqual([
      "apps/api:express",
      "apps/web:nextjs",
      "services/flask:flask",
      "services/gin:gin",
      "services/gin:net-http",
      "services/java:spring",
      "services/kotlin:spring",
      "services/laravel:laravel",
      "services/mvc:spring",
      "services/py:django",
      "services/rails:rails",
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

  it("dates Go's net/http by the toolchain the module declares", () => {
    expect(by("net-http")[0]).toMatchObject({ version: "1.22", versionSource: "toolchain" });
  });

  it("honours the prune predicate", () => {
    expect(detectFrameworks(MONOREPO, (rel) => rel.startsWith("services/")).map((f) => f.id)).toEqual(["express", "nextjs"]);
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
