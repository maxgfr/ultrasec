import { describe, it, expect } from "vitest";
import { findSinks } from "../src/catalog.js";
import { langForFile } from "../src/lang.js";

// `search` is the most over-loaded method name in the catalog, and the LDAP rule
// claimed it with a receiver list containing `client`/`conn`/`connection`. On one
// real repo that produced 17 high-severity "LDAP injection" candidates, every one
// of them an Elasticsearch `client.search()` or a bare `search(opts)` helper —
// noise that buried the findings that mattered.
//
// Two gates fix it without narrowing genuine LDAP detection: the call must have a
// receiver, and the file must import an LDAP module. The receiver list stays
// permissive on purpose — an ldapjs client really is usually named `client`.

const js = langForFile("x.js")!;
const py = langForFile("x.py")!;
const isLdap = (hits: ReturnType<typeof findSinks>) => hits.some((h) => h.kind === "ldap");

const LDAP_JS = [{ spec: "ldapjs" }];
const ES_JS = [{ spec: "@elastic/elasticsearch" }];

describe("the LDAP sink no longer claims every search()", () => {
  it("still fires on a real ldapjs client", () => {
    expect(isLdap(findSinks(js, [{ callee: "search", receiver: "client", line: 1 }], undefined, LDAP_JS))).toBe(true);
    expect(isLdap(findSinks(js, [{ callee: "bind", receiver: "ldapClient", line: 1 }], undefined, LDAP_JS))).toBe(true);
  });

  it("ignores an Elasticsearch client.search() — same shape, different technology", () => {
    expect(isLdap(findSinks(js, [{ callee: "search", receiver: "client", line: 1 }], undefined, ES_JS))).toBe(false);
    expect(isLdap(findSinks(py, [{ callee: "search", receiver: "client", line: 1 }], undefined, [{ spec: "elasticsearch" }]))).toBe(false);
  });

  it("ignores a bare search(opts) — a receiverless call is never an LDAP query", () => {
    expect(isLdap(findSinks(js, [{ callee: "search", receiver: undefined, line: 1 }], undefined, LDAP_JS))).toBe(false);
  });

  it("matches the LDAP module by substring, across ecosystems", () => {
    for (const spec of ["ldapjs", "ldap3", "python-ldap", "activedirectory2", "com.unboundid.ldap.sdk"]) {
      expect(isLdap(findSinks(js, [{ callee: "search", receiver: "conn", line: 1 }], undefined, [{ spec }])), spec).toBe(true);
    }
  });

  it("keeps firing when imports were not extracted at all", () => {
    // An empty import list means the extractor couldn't see them (regex tier),
    // NOT that the file imports nothing — so the gate must not suppress the rule.
    expect(isLdap(findSinks(js, [{ callee: "search", receiver: "ldap", line: 1 }], undefined, []))).toBe(true);
    expect(isLdap(findSinks(js, [{ callee: "search", receiver: "ldap", line: 1 }]))).toBe(true);
  });

  it("leaves rules without requireModule untouched", () => {
    // The mongo rule shares the `client`-ish receiver style and must be unaffected.
    const hits = findSinks(js, [{ callee: "find", receiver: "db", line: 1 }], undefined, ES_JS);
    expect(hits.some((h) => h.kind === "nosql")).toBe(true);
  });
});
