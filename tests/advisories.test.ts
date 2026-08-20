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
const cacheDir3 = mkdtempSync(join(tmpdir(), "pmsec-test-cache3-"));
const cacheDir4 = mkdtempSync(join(tmpdir(), "pmsec-test-cache4-"));

afterAll(() => {
  rmSync(cacheDir1, { recursive: true, force: true });
  rmSync(cacheDir2, { recursive: true, force: true });
  rmSync(cacheDir3, { recursive: true, force: true });
  rmSync(cacheDir4, { recursive: true, force: true });
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

test("lockless projects do not share a digest cache hit", async () => {
  const calls: string[][] = [];
  const cache = createFsCache(cacheDir3, () => 1_000, 86_400_000);
  const locklessPnpm: Project = {
    root: "/a",
    gitRoot: "/a",
    managers: [
      {
        name: "pnpm",
        role: "primary",
        manifestPath: "/a/package.json",
        lockfilePath: null,
        configPath: null,
      },
    ],
  };
  const unreadNpm: Project = {
    root: "/b",
    gitRoot: "/b",
    managers: [
      {
        name: "npm",
        role: "primary",
        manifestPath: "/b/package.json",
        lockfilePath: "/b/package-lock.json",
        configPath: null,
      },
    ],
  };
  const digest = (bytes: string) => `d:${bytes}`;
  await auditAdvisories(locklessPnpm, loadPolicy({}), {
    cache,
    now: () => 1_000,
    digest,
    readFile: () => null,
    run: async (argv) => {
      calls.push(argv);
      return { code: 0, stdout: `{"advisories":{}}`, stderr: "" };
    },
  });
  const second = await auditAdvisories(unreadNpm, loadPolicy({}), {
    cache,
    now: () => 1_000,
    digest,
    readFile: () => null,
    run: async (argv) => {
      calls.push(argv);
      return { code: 0, stdout: `{"advisories":{}}`, stderr: "" };
    },
  });
  expect(second.fromCache).toBe(false);
  expect(second.ranLive).toBe(true);
  expect(calls).toHaveLength(2);
  expect(calls[1]).toEqual(["npm", "audit", "--json"]);
});

test("uv json with deprecated and quarantine statuses emits those finding kinds", async () => {
  const cache = createFsCache(cacheDir4, () => 1_000, 86_400_000);
  const uvProject: Project = {
    root: "/uv",
    gitRoot: "/uv",
    managers: [
      {
        name: "uv",
        role: "primary",
        manifestPath: "/uv/pyproject.toml",
        lockfilePath: "/uv/uv.lock",
        configPath: "/uv/uv.toml",
      },
    ],
  };
  const result = await auditAdvisories(uvProject, loadPolicy({}), {
    cache,
    now: () => 1_000,
    digest: () => "uv-digest",
    readFile: () => "lock",
    run: async () => ({
      code: 0,
      stdout: JSON.stringify([
        { name: "oldpkg", version: "1.0.0", status: "deprecated" },
        { name: "badpkg", version: "2.0.0", status: "quarantine" },
      ]),
      stderr: "",
    }),
  });
  expect(result.findings.some((f) => f.kind === "deprecated")).toBe(true);
  expect(result.findings.some((f) => f.kind === "quarantine")).toBe(true);
});
