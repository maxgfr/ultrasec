import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { detectFormat, parseLine } from "../src/logs/detect.js";

const FIXTURES = join(import.meta.dirname, "fixtures", "logs");
const nginxLines = readFileSync(join(FIXTURES, "nginx-combined.log"), "utf8").split("\n").filter(Boolean);
const jsonLines = readFileSync(join(FIXTURES, "app.jsonl"), "utf8").split("\n").filter(Boolean);
const authLines = readFileSync(join(FIXTURES, "auth.log"), "utf8").split("\n").filter(Boolean);

describe("detectFormat", () => {
  it("votes nginx-combined for the combined-log fixture", () => {
    expect(detectFormat(nginxLines)).toBe("nginx-combined");
  });

  it("votes json-lines for the app.jsonl fixture", () => {
    expect(detectFormat(jsonLines)).toBe("json-lines");
  });

  it("votes generic for a leading-ISO-8601 timestamp file", () => {
    const lines = [
      "2024-01-02T10:00:00Z INFO server started",
      "2024-01-02T10:00:05Z INFO health check ok",
      "2024-01-02T10:00:10Z WARN slow response",
      "[2024-01-02 10:00:12] INFO another style also counts as generic",
    ];
    expect(detectFormat(lines)).toBe("generic");
  });

  it("falls back to raw for unstructured text", () => {
    const lines = ["hello world", "this is not a log line", "just some free text", "nothing structured here"];
    expect(detectFormat(lines)).toBe("raw");
  });

  it("falls back to raw on an empty sample", () => {
    expect(detectFormat([])).toBe("raw");
    expect(detectFormat(["", "   ", "\t"])).toBe("raw");
  });

  it("votes syslog for the classic BSD auth.log fixture", () => {
    expect(detectFormat(authLines)).toBe("syslog");
  });

  it("votes syslog for RFC5424-framed lines", () => {
    const lines = [
      "<34>1 2023-10-11T22:14:15.003Z myhost sshd 1024 - - Failed password for root from 10.1.1.1 port 4 ssh2",
      "<34>1 2023-10-11T22:14:16.003Z myhost sshd 1025 - - Accepted password for root from 10.1.1.1 port 5 ssh2",
      "<86>1 2023-10-11T22:14:20.000Z myhost CRON 2001 - - (root) CMD (/usr/bin/certbot renew)",
    ];
    expect(detectFormat(lines)).toBe("syslog");
  });
});

describe("parseLine — nginx-combined / common", () => {
  it("extracts ip/method/path/status/ua from a combined line", () => {
    const line = nginxLines.find((l) => l.includes('"GET /about HTTP/1.1"'))!;
    const ev = parseLine("nginx-combined", line);
    expect(ev.ip).toBe("10.0.0.6");
    expect(ev.method).toBe("GET");
    expect(ev.path).toBe("/about");
    expect(ev.status).toBe(200);
    expect(ev.ua).toContain("Macintosh");
    expect(ev.raw).toBe(line);
  });

  it("degrades a malformed line to message/raw", () => {
    const line = "this does not look like an access log line at all";
    const ev = parseLine("nginx-combined", line);
    expect(ev).toEqual({ message: line, raw: line });
  });
});

describe("parseLine — json-lines", () => {
  it("maps common keys (ip/path/status/ts/message)", () => {
    const line = jsonLines.find((l) => l.includes('"path":"/api/users"'))!;
    const ev = parseLine("json-lines", line);
    expect(ev.ip).toBe("10.0.1.2");
    expect(ev.path).toBe("/api/users");
    expect(ev.status).toBe(200);
    expect(ev.ts).toBe("2024-01-02T10:01:00Z");
    expect(ev.message).toBe("request handled");
  });

  it("degrades a non-JSON or non-object line to message/raw", () => {
    expect(parseLine("json-lines", "not json at all")).toEqual({ message: "not json at all", raw: "not json at all" });
    expect(parseLine("json-lines", "[1,2,3]")).toEqual({ message: "[1,2,3]", raw: "[1,2,3]" });
  });
});

describe("parseLine — syslog", () => {
  it("extracts ts (no fabricated year/tz) and the sshd 'from <ip>' phrasing", () => {
    const line = authLines.find((l) => l.includes("Failed password"))!;
    const ev = parseLine("syslog", line);
    expect(ev.ts).toBe("Oct 10 13:55:00");
    expect(ev.ip).toBe("198.51.100.200");
    expect(ev.message).toContain("Failed password for invalid user admin");
    expect(ev.raw).toBe(line);
  });

  it("extracts the ip from an 'Accepted password ... from <ip>' line", () => {
    const line = authLines.find((l) => l.includes("Accepted password"))!;
    const ev = parseLine("syslog", line);
    expect(ev.ip).toBe("198.51.100.200");
  });

  it("has no ip when the line carries no 'from <ip>' phrasing", () => {
    const line = authLines.find((l) => l.includes("CRON"))!;
    const ev = parseLine("syslog", line);
    expect(ev.ip).toBeUndefined();
    expect(ev.ts).toBe("Oct 10 14:00:00");
  });

  it("never fabricates a year/timezone — ts is exactly the wire substring", () => {
    const line = authLines.find((l) => l.includes("Failed password"))!;
    const ev = parseLine("syslog", line);
    expect(ev.ts).not.toMatch(/\d{4}/); // no 4-digit year anywhere
  });

  it("parses an RFC5424-framed line: ts from the header, ip from sshd phrasing", () => {
    const line = "<34>1 2023-10-11T22:14:15.003Z myhost sshd 1024 - - Failed password for root from 10.1.1.1 port 4 ssh2";
    const ev = parseLine("syslog", line);
    expect(ev.ts).toBe("2023-10-11T22:14:15.003Z");
    expect(ev.ip).toBe("10.1.1.1");
  });

  it("degrades an unrecognized line to message/raw", () => {
    const line = "this is not a syslog line at all";
    expect(parseLine("syslog", line)).toEqual({ message: line, raw: line });
  });
});

describe("parseLine — generic / raw", () => {
  it("extracts a leading ISO-8601 timestamp for generic", () => {
    const ev = parseLine("generic", "2024-01-02T10:00:00Z INFO server started");
    expect(ev.ts).toBe("2024-01-02T10:00:00Z");
    expect(ev.message).toBe("2024-01-02T10:00:00Z INFO server started");
  });

  it("extracts a bracketed leading date for generic", () => {
    const ev = parseLine("generic", "[2024-01-02 10:00:12] INFO another style");
    expect(ev.ts).toBe("2024-01-02 10:00:12");
  });

  it("raw always degrades to message/raw", () => {
    const line = "anything goes here";
    expect(parseLine("raw", line)).toEqual({ message: line, raw: line });
  });
});
