import { describe, it, expect } from "vitest";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanRepo } from "../src/scan.js";
import { buildGraph } from "../src/graph.js";
import { enumerateTaint } from "../src/taint.js";

// C/C++ had no taint source but `getenv`: the `buffer` sink existed, nothing
// could reach it, and a native target scanned to zero candidates. argv and the
// read family are where a C program's untrusted bytes come from.

function repo(body: string): string {
  const root = mkdtempSync(join(tmpdir(), "ultrasec-c-"));
  mkdirSync(join(root, "src"), { recursive: true });
  writeFileSync(join(root, "src", "main.c"), body);
  return root;
}

function flows(root: string): { kind: string; sink: string }[] {
  const scan = scanRepo(root);
  return enumerateTaint(scan, buildGraph(scan)).findings.map((f) => ({ kind: f.source?.kind ?? "?", sink: f.cwe ?? "?" }));
}

describe("C/C++ taint sources", () => {
  it("flows argv into an unbounded copy", () => {
    const found = flows(
      repo(`#include <string.h>
int main(int argc, char **argv) {
  char buf[16];
  char *name = argv[1];
  strcpy(buf, name);
  return 0;
}
`),
    );
    expect(found).toContainEqual({ kind: "cli", sink: "CWE-120" });
  });

  it("flows a socket read into an unbounded copy", () => {
    const found = flows(
      repo(`#include <string.h>
#include <sys/socket.h>
void handle(int fd) {
  char in[512];
  char out[16];
  int n = recv(fd, in, sizeof in, 0);
  char *msg = in;
  strcpy(out, msg);
}
`),
    );
    expect(found.map((f) => f.sink)).toContain("CWE-120");
  });

  it("does not take a method named read on an object for a source", () => {
    const found = flows(
      repo(`#include <string.h>
void f(Reader *r) {
  char out[16];
  char *s = r->read(4);
  strcpy(out, s);
}
`),
    );
    expect(found).toEqual([]);
  });
});
