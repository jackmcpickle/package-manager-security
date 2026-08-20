import { afterAll, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createFsCache, type AdvisoryResult } from "../src/cache";

const cacheDir = mkdtempSync(join(tmpdir(), "pmsec-cache-unit-"));

afterAll(() => {
  rmSync(cacheDir, { recursive: true, force: true });
});

const emptyResult: AdvisoryResult = {
  findings: [],
  fromCache: false,
  ranLive: true,
};

test("lockfile digest is returned within TTL and missed after expiry", () => {
  let now = 1_000;
  const cache = createFsCache(cacheDir, () => now, 86_400_000);
  cache.putLockfile("abc", emptyResult);
  expect(cache.getLockfile("abc")).toEqual(emptyResult);
  now = 1_000 + 86_400_000;
  expect(cache.getLockfile("abc")).toBeNull();
});

test("a corrupt lockfile cache entry is treated as a miss", () => {
  const dir = join(cacheDir, "corrupt");
  const cache = createFsCache(dir, () => 1_000, 86_400_000);
  mkdirSync(join(dir, "lockfile"), { recursive: true });
  writeFileSync(join(dir, "lockfile", `${encodeURIComponent("abc")}.json`), "{not-json");
  expect(cache.getLockfile("abc")).toBeNull();
});

test("package@version rows round-trip inside TTL", () => {
  const cache = createFsCache(cacheDir, () => 1_000, 86_400_000);
  const rows = [{ name: "left-pad", version: "1.0.0", severity: "high", id: "GHSA-x" }];
  cache.putPackage("left-pad", "1.0.0", rows);
  expect(cache.getPackage("left-pad", "1.0.0")).toEqual(rows);
  expect(cache.getPackage("left-pad", "9.9.9")).toBeNull();
});
