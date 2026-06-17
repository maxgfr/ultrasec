import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanRepo, scanRepoCached } from "../src/scan.js";
import { loadScanCache, saveScanCache, CACHE_VERSION, type CacheEntry } from "../src/cache.js";

describe("scan cache (--resume)", () => {
  let repo: string;
  beforeAll(() => {
    repo = mkdtempSync(join(tmpdir(), "ultrasec-cache-"));
    mkdirSync(join(repo, "src"), { recursive: true });
    writeFileSync(join(repo, "src", "a.js"), "export function a(){ return query(req.query.x); }\n");
    writeFileSync(join(repo, "src", "b.js"), "export function b(){ return 2; }\n");
  });
  afterAll(() => rmSync(repo, { recursive: true, force: true }));

  it("a cached scan equals a fresh scan (determinism)", () => {
    const cache = new Map<string, CacheEntry>();
    const cached = scanRepoCached(repo, {}, cache);
    const fresh = scanRepo(repo, {});
    expect(cached.files).toEqual(fresh.files);
    expect(cache.size).toBe(cached.files.length);
  });

  it("reuses the SAME FileScan object on a hit (no re-extract)", () => {
    const cache = new Map<string, CacheEntry>();
    scanRepoCached(repo, {}, cache); // populate
    const before = cache.get("src/b.js")!.fileScan;
    const second = scanRepoCached(repo, {}, cache); // unchanged → reuse
    const after = second.files.find((f) => f.rel === "src/b.js")!;
    expect(after).toBe(before); // object identity proves the cache hit
  });

  it("re-extracts only the file whose content changed", () => {
    const cache = new Map<string, CacheEntry>();
    scanRepoCached(repo, {}, cache);
    const bBefore = cache.get("src/b.js")!.fileScan;
    const aHashBefore = cache.get("src/a.js")!.hash;

    writeFileSync(join(repo, "src", "a.js"), "export function a(){ return query('static'); }\n");
    scanRepoCached(repo, {}, cache);

    expect(cache.get("src/a.js")!.hash).not.toBe(aHashBefore); // a re-extracted
    expect(cache.get("src/b.js")!.fileScan).toBe(bBefore); // b reused
  });

  it("persists and reloads; a version bump invalidates", () => {
    const run = mkdtempSync(join(tmpdir(), "ultrasec-run-"));
    const cache = new Map<string, CacheEntry>();
    scanRepoCached(repo, {}, cache);
    saveScanCache(run, cache);
    expect(loadScanCache(run).size).toBe(cache.size);

    writeFileSync(join(run, "cache", "scan-cache.json"), JSON.stringify({ cacheVersion: CACHE_VERSION + 99, entries: {} }));
    expect(loadScanCache(run).size).toBe(0); // stale format → ignored
    rmSync(run, { recursive: true, force: true });
  });
});
