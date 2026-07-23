import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanRepo, scanRepoCached } from "../src/scan.js";
import { loadScanCache, saveScanCache, CACHE_VERSION, type CacheEntry } from "../src/cache.js";
import { EXTRACTOR_VERSION } from "../src/vendor/codeindex-engine.mjs";

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
    // Every scanned file has a v2 entry: content hash + the engine's raw record.
    expect(cache.size).toBe(cached.files.length);
    for (const e of cache.values()) {
      expect(typeof e.hash).toBe("string");
      expect(e.record.rel).toBeTruthy();
    }
  });

  it("reuses the SAME engine FileRecord on a hit (no re-extract)", () => {
    const cache = new Map<string, CacheEntry>();
    scanRepoCached(repo, {}, cache); // populate
    const before = cache.get("src/b.js")!.record;
    scanRepoCached(repo, {}, cache); // unchanged → reuse
    const after = cache.get("src/b.js")!.record;
    expect(after).toBe(before); // record identity proves the engine cache hit
  });

  it("re-extracts only the file whose content changed", () => {
    const cache = new Map<string, CacheEntry>();
    scanRepoCached(repo, {}, cache);
    const bBefore = cache.get("src/b.js")!.record;
    const aHashBefore = cache.get("src/a.js")!.hash;

    writeFileSync(join(repo, "src", "a.js"), "export function a(){ return query('static'); }\n");
    scanRepoCached(repo, {}, cache);

    expect(cache.get("src/a.js")!.hash).not.toBe(aHashBefore); // a re-extracted
    expect(cache.get("src/b.js")!.record).toBe(bBefore); // b reused
  });

  it("persists and reloads; a cacheVersion bump invalidates", () => {
    const run = mkdtempSync(join(tmpdir(), "ultrasec-run-"));
    const cache = new Map<string, CacheEntry>();
    scanRepoCached(repo, {}, cache);
    saveScanCache(run, cache);
    expect(loadScanCache(run).size).toBe(cache.size);

    writeFileSync(
      join(run, "cache", "scan-cache.json"),
      JSON.stringify({ cacheVersion: CACHE_VERSION + 99, extractorVersion: EXTRACTOR_VERSION, entries: {} }),
    );
    expect(loadScanCache(run).size).toBe(0); // stale format → ignored
    rmSync(run, { recursive: true, force: true });
  });

  it("an extractorVersion mismatch invalidates the cache (stale extraction never replayed)", () => {
    const run = mkdtempSync(join(tmpdir(), "ultrasec-run-"));
    const cache = new Map<string, CacheEntry>();
    scanRepoCached(repo, {}, cache);
    saveScanCache(run, cache);

    const path = join(run, "cache", "scan-cache.json");
    const data = JSON.parse(readFileSync(path, "utf8"));
    expect(data.extractorVersion).toBe(EXTRACTOR_VERSION); // it was embedded
    data.extractorVersion = EXTRACTOR_VERSION + 1; // simulate a future engine re-pin
    writeFileSync(path, JSON.stringify(data));
    expect(loadScanCache(run).size).toBe(0);
    rmSync(run, { recursive: true, force: true });
  });
});
