import { afterAll, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { createFsCache } from "../src/cache";
import type { AdvisoryResult } from "../src/cache";

const cacheDir = mkdtempSync(path.join(tmpdir(), "pmguard-cache-unit-"));

afterAll(() => {
  rmSync(cacheDir, { force: true, recursive: true });
});

const emptyResult: AdvisoryResult = {
  findings: [],
  fromCache: false,
  ranLive: true,
};

test("lockfile digest is returned within TTL and missed after expiry", () => {
  let now = 1000;
  const cache = createFsCache(cacheDir, () => now, 86_400_000);
  cache.putLockfile("abc", emptyResult);
  expect(cache.getLockfile("abc")).toEqual(emptyResult);
  now = 1000 + 86_400_000;
  expect(cache.getLockfile("abc")).toBeNull();
});

test("a corrupt lockfile cache entry is treated as a miss", () => {
  const dir = path.join(cacheDir, "corrupt");
  const cache = createFsCache(dir, () => 1000, 86_400_000);
  mkdirSync(path.join(dir, "lockfile"), { recursive: true });
  writeFileSync(
    path.join(dir, "lockfile", `${encodeURIComponent("abc")}.json`),
    "{not-json"
  );
  expect(cache.getLockfile("abc")).toBeNull();
});

test("package@version rows round-trip inside TTL", () => {
  const cache = createFsCache(cacheDir, () => 1000, 86_400_000);
  const rows = [
    { id: "GHSA-x", name: "left-pad", severity: "high", version: "1.0.0" },
  ];
  cache.putPackage("left-pad", "1.0.0", rows);
  expect(cache.getPackage("left-pad", "1.0.0")).toEqual(rows);
  expect(cache.getPackage("left-pad", "9.9.9")).toBeNull();
});
