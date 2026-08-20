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
const cacheDir8 = mkdtempSync(join(tmpdir(), "pmsec-test-cache8-"));

afterAll(() => {
  rmSync(cacheDir1, { recursive: true, force: true });
  rmSync(cacheDir2, { recursive: true, force: true });
  rmSync(cacheDir3, { recursive: true, force: true });
  rmSync(cacheDir4, { recursive: true, force: true });
  rmSync(cacheDir5, { recursive: true, force: true });
  rmSync(cacheDir6, { recursive: true, force: true });
  rmSync(cacheDir7, { recursive: true, force: true });
  rmSync(cacheDir8, { recursive: true, force: true });
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

test("pnpm primary runs `pnpm audit --json` and parses a high advisory", async () => {
  const cache = createFsCache(join(cacheDir8, "pnpm"), () => 1_000, 86_400_000);
  const calls: string[][] = [];
  const pnpmProject: Project = {
    root: "/pn",
    gitRoot: "/pn",
    managers: [
      {
        name: "pnpm",
        role: "primary",
        manifestPath: "/pn/package.json",
        lockfilePath: "/pn/pnpm-lock.yaml",
        configPath: "/pn/pnpm-workspace.yaml",
      },
    ],
  };
  // pnpm's `pnpm audit --json` mirrors npm's classic (v6-style) advisory
  // report: a top-level `advisories` map keyed by numeric advisory id.
  const result = await auditAdvisories(pnpmProject, loadPolicy({}), {
    cache,
    now: () => 1_000,
    digest: () => "pnpm-digest",
    readFile: () => "lock",
    run: async (argv, cwd) => {
      calls.push(argv);
      expect(cwd).toBe("/pn");
      return {
        code: 1,
        stdout: JSON.stringify({
          advisories: {
            "1092": {
              module_name: "minimatch",
              severity: "high",
              github_advisory_id: "GHSA-pnpm-high",
              title: "minimatch high advisory",
              findings: [{ version: "3.0.0" }],
              fixAvailable: { name: "minimatch", version: "3.0.5" },
            },
          },
          metadata: { vulnerabilities: { high: 1 } },
        }),
        stderr: "",
      };
    },
  });
  expect(calls).toEqual([["pnpm", "audit", "--json"]]);
  const advisory = result.findings.find((f) => f.kind === "advisory");
  expect(advisory?.severity).toBe("high");
  expect(advisory?.package).toBe("minimatch");
});

test("bun primary runs `bun audit --json` and parses a critical advisory", async () => {
  const cache = createFsCache(join(cacheDir8, "bun"), () => 1_000, 86_400_000);
  const calls: string[][] = [];
  const bunProject: Project = {
    root: "/bn",
    gitRoot: "/bn",
    managers: [
      {
        name: "bun",
        role: "primary",
        manifestPath: "/bn/package.json",
        lockfilePath: "/bn/bun.lock",
        configPath: "/bn/bunfig.toml",
      },
    ],
  };
  // bun's `bun audit --json` mirrors npm's v7+ advisory report: a
  // `vulnerabilities` map keyed by package name, each with a `via` array.
  const result = await auditAdvisories(bunProject, loadPolicy({}), {
    cache,
    now: () => 1_000,
    digest: () => "bun-digest",
    readFile: () => "lock",
    run: async (argv, cwd) => {
      calls.push(argv);
      expect(cwd).toBe("/bn");
      return {
        code: 1,
        stdout: JSON.stringify({
          auditReportVersion: 2,
          vulnerabilities: {
            "ansi-html": {
              name: "ansi-html",
              severity: "critical",
              range: "<0.0.8",
              via: [
                {
                  github_advisory_id: "GHSA-bun-crit",
                  title: "ansi-html critical advisory",
                  severity: "critical",
                },
              ],
              fixAvailable: { name: "ansi-html", version: "0.0.8" },
            },
          },
        }),
        stderr: "",
      };
    },
  });
  expect(calls).toEqual([["bun", "audit", "--json"]]);
  const advisory = result.findings.find((f) => f.kind === "advisory");
  expect(advisory?.severity).toBe("critical");
  expect(advisory?.package).toBe("ansi-html");
  expect(advisory?.fixVersion).toBe("0.0.8");
});

test("yarn berry primary runs `yarn npm audit --json` and parses a high advisory", async () => {
  const cache = createFsCache(join(cacheDir8, "yarn"), () => 1_000, 86_400_000);
  const calls: string[][] = [];
  const yarnProject: Project = {
    root: "/yn",
    gitRoot: "/yn",
    managers: [
      {
        name: "yarn",
        role: "primary",
        manifestPath: "/yn/package.json",
        lockfilePath: "/yn/yarn.lock",
        configPath: "/yn/.yarnrc.yml",
      },
    ],
  };
  // Yarn Berry's `yarn npm audit --json` emits one tree-reporter node per
  // vulnerability: `{ value: <package>, children: { ID, Issue, Severity, ... } }`.
  const result = await auditAdvisories(yarnProject, loadPolicy({}), {
    cache,
    now: () => 1_000,
    digest: () => "yarn-digest",
    readFile: () => "lock",
    run: async (argv, cwd) => {
      calls.push(argv);
      expect(cwd).toBe("/yn");
      return {
        code: 1,
        stdout: JSON.stringify({
          value: "browserify-sign",
          children: {
            ID: 1094464,
            Issue: "browserify-sign upper bound check issue in dsaVerify",
            URL: "https://github.com/advisories/GHSA-x9w5-v3q2-3rhw",
            Severity: "high",
            "Vulnerable Versions": ">=2.6.0 <=4.2.1",
            "Tree Versions": ["4.2.1"],
            Dependents: ["root-workspace-0b6124@workspace:."],
          },
        }),
        stderr: "",
      };
    },
  });
  expect(calls).toEqual([["yarn", "npm", "audit", "--json"]]);
  const advisory = result.findings.find((f) => f.kind === "advisory");
  expect(advisory?.severity).toBe("high");
  expect(advisory?.package).toBe("browserify-sign");
  expect(advisory?.code).toBe("1094464");
});

test("yarn berry primary parses multi-line NDJSON stdout (real multi-vulnerability output)", async () => {
  const cache = createFsCache(join(cacheDir8, "yarn-ndjson"), () => 1_000, 86_400_000);
  const calls: string[][] = [];
  const yarnProject: Project = {
    root: "/yn-multi",
    gitRoot: "/yn-multi",
    managers: [
      {
        name: "yarn",
        role: "primary",
        manifestPath: "/yn-multi/package.json",
        lockfilePath: "/yn-multi/yarn.lock",
        configPath: "/yn-multi/.yarnrc.yml",
      },
    ],
  };
  // When yarn reports more than one vulnerability, `yarn npm audit --json`
  // emits several newline-delimited JSON objects (one tree-reporter node per
  // line) rather than a single JSON document, so `JSON.parse(stdout)` on the
  // whole string fails and the NDJSON fallback in `parseJson` must split,
  // trim, and parse each line individually.
  const lineOne = JSON.stringify({
    value: "browserify-sign",
    children: {
      ID: 1094464,
      Issue: "browserify-sign upper bound check issue in dsaVerify",
      URL: "https://github.com/advisories/GHSA-x9w5-v3q2-3rhw",
      Severity: "high",
      "Vulnerable Versions": ">=2.6.0 <=4.2.1",
      "Tree Versions": ["4.2.1"],
      Dependents: ["root-workspace-0b6124@workspace:."],
    },
  });
  const lineTwo = JSON.stringify({
    value: "ansi-html",
    children: {
      ID: 1098445,
      Issue: "ansi-html Uncontrolled Resource Consumption",
      URL: "https://github.com/advisories/GHSA-whgm-jr23-g3j9",
      Severity: "critical",
      "Vulnerable Versions": "<0.0.8",
      "Tree Versions": ["0.0.7"],
      "Patched Versions": ">=0.0.8",
      Dependents: ["root-workspace-0b6124@workspace:."],
    },
  });
  const result = await auditAdvisories(yarnProject, loadPolicy({}), {
    cache,
    now: () => 1_000,
    digest: () => "yarn-multi-digest",
    readFile: () => "lock",
    run: async (argv, cwd) => {
      calls.push(argv);
      expect(cwd).toBe("/yn-multi");
      return {
        code: 1,
        stdout: `${lineOne}\n${lineTwo}\n`,
        stderr: "",
      };
    },
  });
  expect(calls).toEqual([["yarn", "npm", "audit", "--json"]]);
  const advisories = result.findings.filter((f) => f.kind === "advisory");
  expect(advisories).toHaveLength(2);
  const browserifySign = advisories.find((f) => f.package === "browserify-sign");
  expect(browserifySign?.severity).toBe("high");
  expect(browserifySign?.code).toBe("1094464");
  const ansiHtml = advisories.find((f) => f.package === "ansi-html");
  expect(ansiHtml?.severity).toBe("critical");
  expect(ansiHtml?.code).toBe("1098445");
  expect(ansiHtml?.fixVersion).toBe("0.0.8");
});

test("yarn berry primary with empty stdout on a clean repo yields no findings without throwing", async () => {
  const cache = createFsCache(join(cacheDir8, "yarn-empty"), () => 1_000, 86_400_000);
  const calls: string[][] = [];
  const yarnProject: Project = {
    root: "/yn-clean",
    gitRoot: "/yn-clean",
    managers: [
      {
        name: "yarn",
        role: "primary",
        manifestPath: "/yn-clean/package.json",
        lockfilePath: "/yn-clean/yarn.lock",
        configPath: "/yn-clean/.yarnrc.yml",
      },
    ],
  };
  // `yarn npm audit --json` on a clean repo exits 0 and prints nothing at
  // all (no JSON, not even `{}`). `parseJson` would throw on empty input,
  // so runPrimaries must treat empty/whitespace stdout as "no findings"
  // rather than an incomplete-audit failure.
  const result = await auditAdvisories(yarnProject, loadPolicy({}), {
    cache,
    now: () => 1_000,
    digest: () => "yarn-empty-digest",
    readFile: () => "lock",
    run: async (argv, cwd) => {
      calls.push(argv);
      expect(cwd).toBe("/yn-clean");
      return { code: 0, stdout: "", stderr: "" };
    },
  });
  expect(calls).toEqual([["yarn", "npm", "audit", "--json"]]);
  expect(result.findings).toEqual([]);
  expect(result.ranLive).toBe(true);
});

test("advisory runner dying (non 0/1 exit code) throws an incomplete-tagged error", async () => {
  const cache = createFsCache(join(cacheDir8, "incomplete"), () => 1_000, 86_400_000);
  const deadProject: Project = {
    root: "/dead",
    gitRoot: "/dead",
    managers: [
      {
        name: "npm",
        role: "primary",
        manifestPath: "/dead/package.json",
        lockfilePath: "/dead/package-lock.json",
        configPath: "/dead/.npmrc",
      },
    ],
  };
  const deps = {
    cache,
    now: () => 1_000,
    digest: () => "dead-digest",
    readFile: () => "lock",
    run: async () => ({ code: 2, stdout: "", stderr: "audit engine crashed" }),
  };
  let caught: unknown;
  try {
    await auditAdvisories(deadProject, loadPolicy({}), deps);
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(Error);
  expect((caught as { incomplete?: boolean }).incomplete).toBe(true);
});

test("live advisory argv is one native command per manager", async () => {
  const cases: Array<{ name: "npm" | "pnpm" | "yarn" | "bun" | "uv"; argv: string[] }> = [
    { name: "npm", argv: ["npm", "audit", "--json"] },
    { name: "pnpm", argv: ["pnpm", "audit", "--json"] },
    { name: "yarn", argv: ["yarn", "npm", "audit", "--json"] },
    { name: "bun", argv: ["bun", "audit", "--json"] },
    { name: "uv", argv: ["uv", "audit", "--output-format", "json", "--frozen"] },
  ];
  for (const row of cases) {
    const calls: string[][] = [];
    const cache = createFsCache(join(cacheDir8, `argv-${row.name}`), () => 1_000, 86_400_000);
    await auditAdvisories(
      {
        root: `/${row.name}`,
        gitRoot: `/${row.name}`,
        managers: [
          {
            name: row.name,
            role: "primary",
            manifestPath: `/${row.name}/manifest`,
            lockfilePath: `/${row.name}/lock`,
            configPath: null,
          },
        ],
      },
      loadPolicy({}),
      {
        cache,
        now: () => 1_000,
        digest: () => `${row.name}-argv`,
        readFile: () => "lock",
        run: async (argv) => {
          calls.push(argv);
          return { code: 0, stdout: "{}", stderr: "" };
        },
      },
    );
    expect(calls).toEqual([row.argv]);
  }
});

test("advisory runner throwing also surfaces an incomplete-tagged error", async () => {
  const cache = createFsCache(join(cacheDir8, "throws"), () => 1_000, 86_400_000);
  const throwsProject: Project = {
    root: "/throws",
    gitRoot: "/throws",
    managers: [
      {
        name: "npm",
        role: "primary",
        manifestPath: "/throws/package.json",
        lockfilePath: "/throws/package-lock.json",
        configPath: "/throws/.npmrc",
      },
    ],
  };
  const deps = {
    cache,
    now: () => 1_000,
    digest: () => "throws-digest",
    readFile: () => "lock",
    run: async () => {
      throw new Error("ENOENT: npm not found");
    },
  };
  let caught: unknown;
  try {
    await auditAdvisories(throwsProject, loadPolicy({}), deps);
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(Error);
  expect((caught as { incomplete?: boolean }).incomplete).toBe(true);
});
