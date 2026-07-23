import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { detectFormat, parseLine } from "../src/logs/detect.js";

const FIXTURES = join(import.meta.dirname, "fixtures", "logs");
const nginxLines = readFileSync(join(FIXTURES, "nginx-combined.log"), "utf8").split("\n").filter(Boolean);
const jsonLines = readFileSync(join(FIXTURES, "app.jsonl"), "utf8").split("\n").filter(Boolean);

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
