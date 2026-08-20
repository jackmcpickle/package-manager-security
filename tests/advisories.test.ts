import { afterAll, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { auditAdvisories } from "../src/advisories";
import { createFsCache } from "../src/cache";
import type { Project } from "../src/domain";
import { loadPolicy } from "../src/policy";

const cacheDir1 = mkdtempSync(join(tmpdir(), "pmsec-test-cache-"));
const cacheDir2 = mkdtempSync(join(tmpdir(), "pmsec-test-cache2-"));

afterAll(() => {
  rmSync(cacheDir1, { recursive: true, force: true });
  rmSync(cacheDir2, { recursive: true, force: true });
});

const project: Project = {
  root: "/p",
  gitRoot: "/p",
  managers: [
    {
      name: "pnpm",
      role: "primary",
      manifestPath: "/p/package.json",
      lockfilePath: "/p/pnpm-lock.yaml",
      configPath: "/p/pnpm-workspace.yaml",
    },
  ],
};

test("identical lockfile digest within TTL skips the live runner", async () => {
  const calls: string[][] = [];
  const cache = createFsCache(cacheDir1, () => 1_000, 86_400_000);
  const deps = {
    cache,
    now: () => 1_000,
    digest: () => "abc",
    readFile: () => "lock",
    run: async (argv: string[]) => {
      calls.push(argv);
      return { code: 0, stdout: `{"advisories":{}}`, stderr: "" };
    },
  };
  await auditAdvisories(project, loadPolicy({}), deps);
  deps.now = () => 2_000;
  const second = await auditAdvisories(project, loadPolicy({}), deps);
  expect(second.fromCache).toBe(true);
  expect(second.ranLive).toBe(false);
  expect(calls).toHaveLength(1);
});

test("package@version cache hit still runs live audit", async () => {
  const calls: string[][] = [];
  const cache = createFsCache(cacheDir2, () => 1_000, 86_400_000);
  cache.putPackage("left-pad", "1.0.0", [{ name: "left-pad", version: "1.0.0", severity: "high", id: "GHSA-x" }]);
  // project lockfile digest unique
  const result = await auditAdvisories(project, loadPolicy({}), {
    cache,
    now: () => 1_000,
    digest: () => "unique-digest",
    readFile: () => "other-lock",
    run: async (argv) => {
      calls.push(argv);
      return { code: 0, stdout: `{"advisories":{}}`, stderr: "" };
    },
  });
  expect(result.ranLive).toBe(true);
  expect(calls.length).toBeGreaterThan(0);
});
