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
const cacheDir5 = mkdtempSync(join(tmpdir(), "pmsec-test-cache5-"));
const cacheDir6 = mkdtempSync(join(tmpdir(), "pmsec-test-cache6-"));
const cacheDir7 = mkdtempSync(join(tmpdir(), "pmsec-test-cache7-"));

afterAll(() => {
  rmSync(cacheDir1, { recursive: true, force: true });
  rmSync(cacheDir2, { recursive: true, force: true });
  rmSync(cacheDir3, { recursive: true, force: true });
  rmSync(cacheDir4, { recursive: true, force: true });
  rmSync(cacheDir5, { recursive: true, force: true });
  rmSync(cacheDir6, { recursive: true, force: true });
  rmSync(cacheDir7, { recursive: true, force: true });
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

test("digest cache hit still runs live audit when refresh or noCache is set", async () => {
  const calls: string[][] = [];
  const cache = createFsCache(cacheDir6, () => 1_000, 86_400_000);
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
  expect(calls).toHaveLength(1);

  const refreshed = await auditAdvisories(project, loadPolicy({}), { ...deps, refresh: true });
  expect(refreshed.ranLive).toBe(true);
  expect(refreshed.fromCache).toBe(false);
  expect(calls).toHaveLength(2);

  const uncached = await auditAdvisories(project, loadPolicy({}), { ...deps, noCache: true });
  expect(uncached.ranLive).toBe(true);
  expect(uncached.fromCache).toBe(false);
  expect(calls).toHaveLength(3);
});

test("noCache skips writing the lockfile digest cache", async () => {
  const calls: string[][] = [];
  const cache = createFsCache(cacheDir7, () => 1_000, 86_400_000);
  const deps = {
    cache,
    now: () => 1_000,
    digest: () => "no-cache-digest",
    readFile: () => "lock",
    run: async (argv: string[]) => {
      calls.push(argv);
      return { code: 0, stdout: `{"advisories":{}}`, stderr: "" };
    },
  };
  await auditAdvisories(project, loadPolicy({}), { ...deps, noCache: true });
  expect(calls).toHaveLength(1);
  const second = await auditAdvisories(project, loadPolicy({}), deps);
  expect(second.ranLive).toBe(true);
  expect(second.fromCache).toBe(false);
  expect(calls).toHaveLength(2);
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

test("npm audit JSON populates package currentVersion and fixVersion on findings", async () => {
  const cache = createFsCache(join(cacheDir4, "versions"), () => 1_000, 86_400_000);
  const npmProject: Project = {
    root: "/p",
    gitRoot: "/p",
    managers: [
      {
        name: "npm",
        role: "primary",
        manifestPath: "/p/package.json",
        lockfilePath: "/p/package-lock.json",
        configPath: "/p/.npmrc",
      },
    ],
  };
  const result = await auditAdvisories(npmProject, loadPolicy({}), {
    cache,
    now: () => 1_000,
    digest: () => "npm-versions",
    readFile: () => "lock",
    run: async () => ({
      code: 1,
      stdout: JSON.stringify({
        advisories: {
          "1": {
            module_name: "left-pad",
            severity: "high",
            github_advisory_id: "GHSA-left-pad",
            title: "left-pad high advisory",
            findings: [{ version: "1.0.0" }],
            fixAvailable: { name: "left-pad", version: "1.3.0" },
          },
        },
      }),
      stderr: "",
    }),
  });
  const finding = result.findings.find((row) => row.kind === "advisory");
  expect(finding?.package).toBe("left-pad");
  expect(finding?.currentVersion).toBe("1.0.0");
  expect(finding?.fixVersion).toBe("1.3.0");
});

test("advisory range is not used as the installed currentVersion", async () => {
  const cache = createFsCache(join(cacheDir4, "range"), () => 1_000, 86_400_000);
  const npmProject: Project = {
    root: "/p",
    gitRoot: "/p",
    managers: [
      {
        name: "npm",
        role: "primary",
        manifestPath: "/p/package.json",
        lockfilePath: "/p/package-lock.json",
        configPath: "/p/.npmrc",
      },
    ],
  };
  const result = await auditAdvisories(npmProject, loadPolicy({}), {
    cache,
    now: () => 1_000,
    digest: () => "npm-range",
    readFile: () => "lock",
    run: async () => ({
      code: 1,
      stdout: JSON.stringify({
        vulnerabilities: {
          "left-pad": {
            name: "left-pad",
            severity: "high",
            range: ">=1.0.0 <2.0.0",
            fixAvailable: { name: "left-pad", version: "1.3.0" },
            via: [
              {
                github_advisory_id: "GHSA-left-pad",
                title: "left-pad high advisory",
                severity: "high",
              },
            ],
          },
        },
      }),
      stderr: "",
    }),
  });
  const finding = result.findings.find((row) => row.kind === "advisory");
  expect(finding?.package).toBe("left-pad");
  expect(finding?.currentVersion).toBeUndefined();
  expect(finding?.currentVersion).not.toBe(">=1.0.0 <2.0.0");
  expect(finding?.fixVersion).toBe("1.3.0");
});

test("range-like version fields never become currentVersion", async () => {
  const cache = createFsCache(join(cacheDir4, "range-fields"), () => 1_000, 86_400_000);
  const npmProject: Project = {
    root: "/p",
    gitRoot: "/p",
    managers: [
      {
        name: "npm",
        role: "primary",
        manifestPath: "/p/package.json",
        lockfilePath: "/p/package-lock.json",
        configPath: "/p/.npmrc",
      },
    ],
  };
  const vulns = await auditAdvisories(npmProject, loadPolicy({}), {
    cache,
    now: () => 1_000,
    digest: () => "npm-range-vulns",
    readFile: () => "lock",
    run: async () => ({
      code: 1,
      stdout: JSON.stringify({
        vulnerabilities: {
          "left-pad": {
            name: "left-pad",
            version: "<=2.0.0",
            package: { name: "left-pad", version: "^1.2.3" },
            vulns: [{ id: "GHSA-left-pad", severity: "high", title: "left-pad high advisory" }],
            fixAvailable: { name: "left-pad", version: "1.3.0" },
          },
        },
      }),
      stderr: "",
    }),
  });
  const vulnFinding = vulns.findings.find((row) => row.kind === "advisory");
  expect(vulnFinding?.currentVersion).toBeUndefined();
  expect(vulnFinding?.currentVersion).not.toBe("<=2.0.0");
  expect(vulnFinding?.currentVersion).not.toBe("^1.2.3");

  const findings = await auditAdvisories(npmProject, loadPolicy({}), {
    cache,
    now: () => 2_000,
    digest: () => "npm-range-findings",
    readFile: () => "lock",
    run: async () => ({
      code: 1,
      stdout: JSON.stringify({
        advisories: {
          "1": {
            module_name: "left-pad",
            severity: "high",
            github_advisory_id: "GHSA-left-pad",
            title: "left-pad high advisory",
            findings: [{ version: "^1.2.3" }],
            fixAvailable: { name: "left-pad", version: "1.3.0" },
          },
        },
      }),
      stderr: "",
    }),
  });
  const finding = findings.findings.find((row) => row.kind === "advisory");
  expect(finding?.currentVersion).toBeUndefined();
  expect(finding?.currentVersion).not.toBe("^1.2.3");
});

test("x-range version fields never become currentVersion", async () => {
  const cache = createFsCache(join(cacheDir4, "x-range"), () => 1_000, 86_400_000);
  const npmProject: Project = {
    root: "/p",
    gitRoot: "/p",
    managers: [
      {
        name: "npm",
        role: "primary",
        manifestPath: "/p/package.json",
        lockfilePath: "/p/package-lock.json",
        configPath: "/p/.npmrc",
      },
    ],
  };
  const result = await auditAdvisories(npmProject, loadPolicy({}), {
    cache,
    now: () => 1_000,
    digest: () => "npm-x-range",
    readFile: () => "lock",
    run: async () => ({
      code: 1,
      stdout: JSON.stringify({
        vulnerabilities: {
          "left-pad": {
            name: "left-pad",
            version: "1.2.x",
            package: { name: "left-pad", version: "1.x" },
            findings: [{ version: "1.2.X" }],
            vulns: [{ id: "GHSA-left-pad", severity: "high", title: "left-pad high advisory" }],
            fixAvailable: { name: "left-pad", version: "1.3.0" },
          },
        },
      }),
      stderr: "",
    }),
  });
  const finding = result.findings.find((row) => row.kind === "advisory");
  expect(finding?.package).toBe("left-pad");
  expect(finding?.currentVersion).toBeUndefined();
  expect(finding?.currentVersion).not.toBe("1.2.x");
  expect(finding?.fixVersion).toBe("1.3.0");
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

test("poetry primary uses runOsv when provided", async () => {
  const cache = createFsCache(cacheDir5, () => 1_000, 86_400_000);
  const poetryProject: Project = {
    root: "/py",
    gitRoot: "/py",
    managers: [
      {
        name: "poetry",
        role: "primary",
        manifestPath: "/py/pyproject.toml",
        lockfilePath: "/py/poetry.lock",
        configPath: "/py/pyproject.toml",
      },
    ],
  };
  const result = await auditAdvisories(poetryProject, loadPolicy({}), {
    cache,
    now: () => 1_000,
    digest: () => "poetry-digest",
    readFile: () => "lock",
    run: async () => ({ code: 0, stdout: `{"advisories":{}}`, stderr: "" }),
    runOsv: async (lockOrRequirements) => {
      expect(lockOrRequirements).toBe("/py/poetry.lock");
      return [
        {
          kind: "advisory",
          code: "GHSA-osv",
          message: "osv high advisory",
          severity: "high",
          path: lockOrRequirements,
          fixable: false,
          manager: "poetry",
        },
      ];
    },
  });
  expect(result.findings.some((f) => f.kind === "advisory" && f.severity === "high")).toBe(true);
});
