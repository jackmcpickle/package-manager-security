import { afterAll, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { auditAdvisories } from "../src/advisories";
import { createFsCache } from "../src/cache";
import type { Project } from "../src/domain";
import { loadPolicy } from "../src/policy";

const cacheDir1 = mkdtempSync(path.join(tmpdir(), "pmsec-test-cache-"));
const cacheDir2 = mkdtempSync(path.join(tmpdir(), "pmsec-test-cache2-"));
const cacheDir3 = mkdtempSync(path.join(tmpdir(), "pmsec-test-cache3-"));
const cacheDir4 = mkdtempSync(path.join(tmpdir(), "pmsec-test-cache4-"));
const cacheDir5 = mkdtempSync(path.join(tmpdir(), "pmsec-test-cache5-"));
const cacheDir6 = mkdtempSync(path.join(tmpdir(), "pmsec-test-cache6-"));
const cacheDir7 = mkdtempSync(path.join(tmpdir(), "pmsec-test-cache7-"));
const cacheDir8 = mkdtempSync(path.join(tmpdir(), "pmsec-test-cache8-"));
const digest = (bytes: string) => `d:${bytes}`;

afterAll(() => {
  rmSync(cacheDir1, { force: true, recursive: true });
  rmSync(cacheDir2, { force: true, recursive: true });
  rmSync(cacheDir3, { force: true, recursive: true });
  rmSync(cacheDir4, { force: true, recursive: true });
  rmSync(cacheDir5, { force: true, recursive: true });
  rmSync(cacheDir6, { force: true, recursive: true });
  rmSync(cacheDir7, { force: true, recursive: true });
  rmSync(cacheDir8, { force: true, recursive: true });
});

const project: Project = {
  gitRoot: "/p",
  managers: [
    {
      configPath: "/p/pnpm-workspace.yaml",
      lockfilePath: "/p/pnpm-lock.yaml",
      manifestPath: "/p/package.json",
      name: "pnpm",
      role: "primary",
    },
  ],
  root: "/p",
};

test("identical lockfile digest within TTL skips the live runner", async () => {
  const calls: string[][] = [];
  const cache = createFsCache(cacheDir1, () => 1000, 86_400_000);
  const deps = {
    cache,
    digest: () => "abc",
    now: () => 1000,
    readFile: () => "lock",
    run: (argv: string[]) => {
      calls.push(argv);
      return { code: 0, stderr: "", stdout: `{"advisories":{}}` };
    },
  };
  await auditAdvisories(project, loadPolicy({}), deps);
  deps.now = () => 2000;
  const second = await auditAdvisories(project, loadPolicy({}), deps);
  expect(second.fromCache).toBe(true);
  expect(second.ranLive).toBe(false);
  expect(calls).toHaveLength(1);
});

test("digest cache hit still runs live audit when refresh or noCache is set", async () => {
  const calls: string[][] = [];
  const cache = createFsCache(cacheDir6, () => 1000, 86_400_000);
  const deps = {
    cache,
    digest: () => "abc",
    now: () => 1000,
    readFile: () => "lock",
    run: (argv: string[]) => {
      calls.push(argv);
      return { code: 0, stderr: "", stdout: `{"advisories":{}}` };
    },
  };
  await auditAdvisories(project, loadPolicy({}), deps);
  expect(calls).toHaveLength(1);

  const refreshed = await auditAdvisories(project, loadPolicy({}), {
    ...deps,
    refresh: true,
  });
  expect(refreshed.ranLive).toBe(true);
  expect(refreshed.fromCache).toBe(false);
  expect(calls).toHaveLength(2);

  const uncached = await auditAdvisories(project, loadPolicy({}), {
    ...deps,
    noCache: true,
  });
  expect(uncached.ranLive).toBe(true);
  expect(uncached.fromCache).toBe(false);
  expect(calls).toHaveLength(3);
});

test("noCache skips writing the lockfile digest cache", async () => {
  const calls: string[][] = [];
  const cache = createFsCache(cacheDir7, () => 1000, 86_400_000);
  const deps = {
    cache,
    digest: () => "no-cache-digest",
    now: () => 1000,
    readFile: () => "lock",
    run: (argv: string[]) => {
      calls.push(argv);
      return { code: 0, stderr: "", stdout: `{"advisories":{}}` };
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
  const cache = createFsCache(cacheDir2, () => 1000, 86_400_000);
  cache.putPackage("left-pad", "1.0.0", [
    { id: "GHSA-x", name: "left-pad", severity: "high", version: "1.0.0" },
  ]);
  // project lockfile digest unique
  const result = await auditAdvisories(project, loadPolicy({}), {
    cache,
    digest: () => "unique-digest",
    now: () => 1000,
    readFile: () => "other-lock",
    run: (argv) => {
      calls.push(argv);
      return { code: 0, stderr: "", stdout: `{"advisories":{}}` };
    },
  });
  expect(result.ranLive).toBe(true);
  expect(calls.length).toBeGreaterThan(0);
});

test("lockless projects do not share a digest cache hit", async () => {
  const calls: string[][] = [];
  const cache = createFsCache(cacheDir3, () => 1000, 86_400_000);
  const locklessPnpm: Project = {
    gitRoot: "/a",
    managers: [
      {
        configPath: null,
        lockfilePath: null,
        manifestPath: "/a/package.json",
        name: "pnpm",
        role: "primary",
      },
    ],
    root: "/a",
  };
  const unreadNpm: Project = {
    gitRoot: "/b",
    managers: [
      {
        configPath: null,
        lockfilePath: "/b/package-lock.json",
        manifestPath: "/b/package.json",
        name: "npm",
        role: "primary",
      },
    ],
    root: "/b",
  };
  await auditAdvisories(locklessPnpm, loadPolicy({}), {
    cache,
    digest,
    now: () => 1000,
    readFile: () => null,
    run: (argv) => {
      calls.push(argv);
      return { code: 0, stderr: "", stdout: `{"advisories":{}}` };
    },
  });
  const second = await auditAdvisories(unreadNpm, loadPolicy({}), {
    cache,
    digest,
    now: () => 1000,
    readFile: () => null,
    run: (argv) => {
      calls.push(argv);
      return { code: 0, stderr: "", stdout: `{"advisories":{}}` };
    },
  });
  expect(second.fromCache).toBe(false);
  expect(second.ranLive).toBe(true);
  expect(calls).toHaveLength(2);
  expect(calls[1]).toEqual(["npm", "audit", "--json"]);
});

test("npm audit JSON populates package currentVersion and fixVersion on findings", async () => {
  const cache = createFsCache(
    path.join(cacheDir4, "versions"),
    () => 1000,
    86_400_000
  );
  const npmProject: Project = {
    gitRoot: "/p",
    managers: [
      {
        configPath: "/p/.npmrc",
        lockfilePath: "/p/package-lock.json",
        manifestPath: "/p/package.json",
        name: "npm",
        role: "primary",
      },
    ],
    root: "/p",
  };
  const result = await auditAdvisories(npmProject, loadPolicy({}), {
    cache,
    digest: () => "npm-versions",
    now: () => 1000,
    readFile: () => "lock",
    run: () => ({
      code: 1,
      stderr: "",
      stdout: JSON.stringify({
        advisories: {
          "1": {
            findings: [{ version: "1.0.0" }],
            fixAvailable: { name: "left-pad", version: "1.3.0" },
            github_advisory_id: "GHSA-left-pad",
            module_name: "left-pad",
            severity: "high",
            title: "left-pad high advisory",
          },
        },
      }),
    }),
  });
  const finding = result.findings.find((row) => row.kind === "advisory");
  expect(finding?.package).toBe("left-pad");
  expect(finding?.currentVersion).toBe("1.0.0");
  expect(finding?.fixVersion).toBe("1.3.0");
});

test("advisory range is not used as the installed currentVersion", async () => {
  const cache = createFsCache(
    path.join(cacheDir4, "range"),
    () => 1000,
    86_400_000
  );
  const npmProject: Project = {
    gitRoot: "/p",
    managers: [
      {
        configPath: "/p/.npmrc",
        lockfilePath: "/p/package-lock.json",
        manifestPath: "/p/package.json",
        name: "npm",
        role: "primary",
      },
    ],
    root: "/p",
  };
  const result = await auditAdvisories(npmProject, loadPolicy({}), {
    cache,
    digest: () => "npm-range",
    now: () => 1000,
    readFile: () => "lock",
    run: () => ({
      code: 1,
      stderr: "",
      stdout: JSON.stringify({
        vulnerabilities: {
          "left-pad": {
            fixAvailable: { name: "left-pad", version: "1.3.0" },
            name: "left-pad",
            range: ">=1.0.0 <2.0.0",
            severity: "high",
            via: [
              {
                github_advisory_id: "GHSA-left-pad",
                severity: "high",
                title: "left-pad high advisory",
              },
            ],
          },
        },
      }),
    }),
  });
  const finding = result.findings.find((row) => row.kind === "advisory");
  expect(finding?.package).toBe("left-pad");
  expect(finding?.currentVersion).toBeUndefined();
  expect(finding?.currentVersion).not.toBe(">=1.0.0 <2.0.0");
  expect(finding?.fixVersion).toBe("1.3.0");
});

test("range-like version fields never become currentVersion", async () => {
  const cache = createFsCache(
    path.join(cacheDir4, "range-fields"),
    () => 1000,
    86_400_000
  );
  const npmProject: Project = {
    gitRoot: "/p",
    managers: [
      {
        configPath: "/p/.npmrc",
        lockfilePath: "/p/package-lock.json",
        manifestPath: "/p/package.json",
        name: "npm",
        role: "primary",
      },
    ],
    root: "/p",
  };
  const vulns = await auditAdvisories(npmProject, loadPolicy({}), {
    cache,
    digest: () => "npm-range-vulns",
    now: () => 1000,
    readFile: () => "lock",
    run: () => ({
      code: 1,
      stderr: "",
      stdout: JSON.stringify({
        vulnerabilities: {
          "left-pad": {
            fixAvailable: { name: "left-pad", version: "1.3.0" },
            name: "left-pad",
            package: { name: "left-pad", version: "^1.2.3" },
            version: "<=2.0.0",
            vulns: [
              {
                id: "GHSA-left-pad",
                severity: "high",
                title: "left-pad high advisory",
              },
            ],
          },
        },
      }),
    }),
  });
  const vulnFinding = vulns.findings.find((row) => row.kind === "advisory");
  expect(vulnFinding?.currentVersion).toBeUndefined();
  expect(vulnFinding?.currentVersion).not.toBe("<=2.0.0");
  expect(vulnFinding?.currentVersion).not.toBe("^1.2.3");

  const findings = await auditAdvisories(npmProject, loadPolicy({}), {
    cache,
    digest: () => "npm-range-findings",
    now: () => 2000,
    readFile: () => "lock",
    run: () => ({
      code: 1,
      stderr: "",
      stdout: JSON.stringify({
        advisories: {
          "1": {
            findings: [{ version: "^1.2.3" }],
            fixAvailable: { name: "left-pad", version: "1.3.0" },
            github_advisory_id: "GHSA-left-pad",
            module_name: "left-pad",
            severity: "high",
            title: "left-pad high advisory",
          },
        },
      }),
    }),
  });
  const finding = findings.findings.find((row) => row.kind === "advisory");
  expect(finding?.currentVersion).toBeUndefined();
  expect(finding?.currentVersion).not.toBe("^1.2.3");
});

test("x-range version fields never become currentVersion", async () => {
  const cache = createFsCache(
    path.join(cacheDir4, "x-range"),
    () => 1000,
    86_400_000
  );
  const npmProject: Project = {
    gitRoot: "/p",
    managers: [
      {
        configPath: "/p/.npmrc",
        lockfilePath: "/p/package-lock.json",
        manifestPath: "/p/package.json",
        name: "npm",
        role: "primary",
      },
    ],
    root: "/p",
  };
  const result = await auditAdvisories(npmProject, loadPolicy({}), {
    cache,
    digest: () => "npm-x-range",
    now: () => 1000,
    readFile: () => "lock",
    run: () => ({
      code: 1,
      stderr: "",
      stdout: JSON.stringify({
        vulnerabilities: {
          "left-pad": {
            findings: [{ version: "1.2.X" }],
            fixAvailable: { name: "left-pad", version: "1.3.0" },
            name: "left-pad",
            package: { name: "left-pad", version: "1.x" },
            version: "1.2.x",
            vulns: [
              {
                id: "GHSA-left-pad",
                severity: "high",
                title: "left-pad high advisory",
              },
            ],
          },
        },
      }),
    }),
  });
  const finding = result.findings.find((row) => row.kind === "advisory");
  expect(finding?.package).toBe("left-pad");
  expect(finding?.currentVersion).toBeUndefined();
  expect(finding?.currentVersion).not.toBe("1.2.x");
  expect(finding?.fixVersion).toBe("1.3.0");
});

test("uv json with deprecated and quarantine statuses emits those finding kinds", async () => {
  const cache = createFsCache(cacheDir4, () => 1000, 86_400_000);
  const uvProject: Project = {
    gitRoot: "/uv",
    managers: [
      {
        configPath: "/uv/uv.toml",
        lockfilePath: "/uv/uv.lock",
        manifestPath: "/uv/pyproject.toml",
        name: "uv",
        role: "primary",
      },
    ],
    root: "/uv",
  };
  const result = await auditAdvisories(uvProject, loadPolicy({}), {
    cache,
    digest: () => "uv-digest",
    now: () => 1000,
    readFile: () => "lock",
    run: () => ({
      code: 0,
      stderr: "",
      stdout: JSON.stringify([
        { name: "oldpkg", status: "deprecated", version: "1.0.0" },
        { name: "badpkg", status: "quarantine", version: "2.0.0" },
      ]),
    }),
  });
  expect(result.findings.some((f) => f.kind === "deprecated")).toBe(true);
  expect(result.findings.some((f) => f.kind === "quarantine")).toBe(true);
});

test("poetry primary uses runOsv when provided", async () => {
  const cache = createFsCache(cacheDir5, () => 1000, 86_400_000);
  const poetryProject: Project = {
    gitRoot: "/py",
    managers: [
      {
        configPath: "/py/pyproject.toml",
        lockfilePath: "/py/poetry.lock",
        manifestPath: "/py/pyproject.toml",
        name: "poetry",
        role: "primary",
      },
    ],
    root: "/py",
  };
  const result = await auditAdvisories(poetryProject, loadPolicy({}), {
    cache,
    digest: () => "poetry-digest",
    now: () => 1000,
    readFile: () => "lock",
    run: () => ({ code: 0, stderr: "", stdout: `{"advisories":{}}` }),
    runOsv: (lockOrRequirements) => {
      expect(lockOrRequirements).toBe("/py/poetry.lock");
      return [
        {
          code: "GHSA-osv",
          fixable: false,
          kind: "advisory",
          manager: "poetry",
          message: "osv high advisory",
          path: lockOrRequirements,
          severity: "high",
        },
      ];
    },
  });
  expect(
    result.findings.some((f) => f.kind === "advisory" && f.severity === "high")
  ).toBe(true);
});

test("pnpm primary runs `pnpm audit --json` and parses a high advisory", async () => {
  const cache = createFsCache(
    path.join(cacheDir8, "pnpm"),
    () => 1000,
    86_400_000
  );
  const calls: string[][] = [];
  const pnpmProject: Project = {
    gitRoot: "/pn",
    managers: [
      {
        configPath: "/pn/pnpm-workspace.yaml",
        lockfilePath: "/pn/pnpm-lock.yaml",
        manifestPath: "/pn/package.json",
        name: "pnpm",
        role: "primary",
      },
    ],
    root: "/pn",
  };
  // pnpm's `pnpm audit --json` mirrors npm's classic (v6-style) advisory
  // report: a top-level `advisories` map keyed by numeric advisory id.
  const result = await auditAdvisories(pnpmProject, loadPolicy({}), {
    cache,
    digest: () => "pnpm-digest",
    now: () => 1000,
    readFile: () => "lock",
    run: (argv, cwd) => {
      calls.push(argv);
      expect(cwd).toBe("/pn");
      return {
        code: 1,
        stderr: "",
        stdout: JSON.stringify({
          advisories: {
            "1092": {
              findings: [{ version: "3.0.0" }],
              fixAvailable: { name: "minimatch", version: "3.0.5" },
              github_advisory_id: "GHSA-pnpm-high",
              module_name: "minimatch",
              severity: "high",
              title: "minimatch high advisory",
            },
          },
          metadata: { vulnerabilities: { high: 1 } },
        }),
      };
    },
  });
  expect(calls).toEqual([["pnpm", "audit", "--json"]]);
  const advisory = result.findings.find((f) => f.kind === "advisory");
  expect(advisory?.severity).toBe("high");
  expect(advisory?.package).toBe("minimatch");
});

test("bun primary runs `bun audit --json` and parses a critical advisory", async () => {
  const cache = createFsCache(
    path.join(cacheDir8, "bun"),
    () => 1000,
    86_400_000
  );
  const calls: string[][] = [];
  const bunProject: Project = {
    gitRoot: "/bn",
    managers: [
      {
        configPath: "/bn/bunfig.toml",
        lockfilePath: "/bn/bun.lock",
        manifestPath: "/bn/package.json",
        name: "bun",
        role: "primary",
      },
    ],
    root: "/bn",
  };
  // bun's `bun audit --json` mirrors npm's v7+ advisory report: a
  // `vulnerabilities` map keyed by package name, each with a `via` array.
  const result = await auditAdvisories(bunProject, loadPolicy({}), {
    cache,
    digest: () => "bun-digest",
    now: () => 1000,
    readFile: () => "lock",
    run: (argv, cwd) => {
      calls.push(argv);
      expect(cwd).toBe("/bn");
      return {
        code: 1,
        stderr: "",
        stdout: JSON.stringify({
          auditReportVersion: 2,
          vulnerabilities: {
            "ansi-html": {
              fixAvailable: { name: "ansi-html", version: "0.0.8" },
              name: "ansi-html",
              range: "<0.0.8",
              severity: "critical",
              via: [
                {
                  github_advisory_id: "GHSA-bun-crit",
                  severity: "critical",
                  title: "ansi-html critical advisory",
                },
              ],
            },
          },
        }),
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
  const cache = createFsCache(
    path.join(cacheDir8, "yarn"),
    () => 1000,
    86_400_000
  );
  const calls: string[][] = [];
  const yarnProject: Project = {
    gitRoot: "/yn",
    managers: [
      {
        configPath: "/yn/.yarnrc.yml",
        lockfilePath: "/yn/yarn.lock",
        manifestPath: "/yn/package.json",
        name: "yarn",
        role: "primary",
      },
    ],
    root: "/yn",
  };
  // Yarn Berry's `yarn npm audit --json` emits one tree-reporter node per
  // vulnerability: `{ value: <package>, children: { ID, Issue, Severity, ... } }`.
  const result = await auditAdvisories(yarnProject, loadPolicy({}), {
    cache,
    digest: () => "yarn-digest",
    now: () => 1000,
    readFile: () => "lock",
    run: (argv, cwd) => {
      calls.push(argv);
      expect(cwd).toBe("/yn");
      return {
        code: 1,
        stderr: "",
        stdout: JSON.stringify({
          children: {
            Dependents: ["root-workspace-0b6124@workspace:."],
            ID: 1_094_464,
            Issue: "browserify-sign upper bound check issue in dsaVerify",
            Severity: "high",
            "Tree Versions": ["4.2.1"],
            URL: "https://github.com/advisories/GHSA-x9w5-v3q2-3rhw",
            "Vulnerable Versions": ">=2.6.0 <=4.2.1",
          },
          value: "browserify-sign",
        }),
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
  const cache = createFsCache(
    path.join(cacheDir8, "yarn-ndjson"),
    () => 1000,
    86_400_000
  );
  const calls: string[][] = [];
  const yarnProject: Project = {
    gitRoot: "/yn-multi",
    managers: [
      {
        configPath: "/yn-multi/.yarnrc.yml",
        lockfilePath: "/yn-multi/yarn.lock",
        manifestPath: "/yn-multi/package.json",
        name: "yarn",
        role: "primary",
      },
    ],
    root: "/yn-multi",
  };
  // When yarn reports more than one vulnerability, `yarn npm audit --json`
  // emits several newline-delimited JSON objects (one tree-reporter node per
  // line) rather than a single JSON document, so `JSON.parse(stdout)` on the
  // whole string fails and the NDJSON fallback in `parseJson` must split,
  // trim, and parse each line individually.
  const lineOne = JSON.stringify({
    children: {
      Dependents: ["root-workspace-0b6124@workspace:."],
      ID: 1_094_464,
      Issue: "browserify-sign upper bound check issue in dsaVerify",
      Severity: "high",
      "Tree Versions": ["4.2.1"],
      URL: "https://github.com/advisories/GHSA-x9w5-v3q2-3rhw",
      "Vulnerable Versions": ">=2.6.0 <=4.2.1",
    },
    value: "browserify-sign",
  });
  const lineTwo = JSON.stringify({
    children: {
      Dependents: ["root-workspace-0b6124@workspace:."],
      ID: 1_098_445,
      Issue: "ansi-html Uncontrolled Resource Consumption",
      "Patched Versions": ">=0.0.8",
      Severity: "critical",
      "Tree Versions": ["0.0.7"],
      URL: "https://github.com/advisories/GHSA-whgm-jr23-g3j9",
      "Vulnerable Versions": "<0.0.8",
    },
    value: "ansi-html",
  });
  const result = await auditAdvisories(yarnProject, loadPolicy({}), {
    cache,
    digest: () => "yarn-multi-digest",
    now: () => 1000,
    readFile: () => "lock",
    run: (argv, cwd) => {
      calls.push(argv);
      expect(cwd).toBe("/yn-multi");
      return {
        code: 1,
        stderr: "",
        stdout: `${lineOne}\n${lineTwo}\n`,
      };
    },
  });
  expect(calls).toEqual([["yarn", "npm", "audit", "--json"]]);
  const advisories = result.findings.filter((f) => f.kind === "advisory");
  expect(advisories).toHaveLength(2);
  const browserifySign = advisories.find(
    (f) => f.package === "browserify-sign"
  );
  expect(browserifySign?.severity).toBe("high");
  expect(browserifySign?.code).toBe("1094464");
  const ansiHtml = advisories.find((f) => f.package === "ansi-html");
  expect(ansiHtml?.severity).toBe("critical");
  expect(ansiHtml?.code).toBe("1098445");
  expect(ansiHtml?.fixVersion).toBe("0.0.8");
});

test("yarn berry primary with empty stdout on a clean repo yields no findings without throwing", async () => {
  const cache = createFsCache(
    path.join(cacheDir8, "yarn-empty"),
    () => 1000,
    86_400_000
  );
  const calls: string[][] = [];
  const yarnProject: Project = {
    gitRoot: "/yn-clean",
    managers: [
      {
        configPath: "/yn-clean/.yarnrc.yml",
        lockfilePath: "/yn-clean/yarn.lock",
        manifestPath: "/yn-clean/package.json",
        name: "yarn",
        role: "primary",
      },
    ],
    root: "/yn-clean",
  };
  // `yarn npm audit --json` on a clean repo exits 0 and prints nothing at
  // all (no JSON, not even `{}`). `parseJson` would throw on empty input,
  // so runPrimaries must treat empty/whitespace stdout as "no findings"
  // rather than an incomplete-audit failure.
  const result = await auditAdvisories(yarnProject, loadPolicy({}), {
    cache,
    digest: () => "yarn-empty-digest",
    now: () => 1000,
    readFile: () => "lock",
    run: (argv, cwd) => {
      calls.push(argv);
      expect(cwd).toBe("/yn-clean");
      return { code: 0, stderr: "", stdout: "" };
    },
  });
  expect(calls).toEqual([["yarn", "npm", "audit", "--json"]]);
  expect(result.findings).toEqual([]);
  expect(result.ranLive).toBe(true);
});

test("advisory runner dying (non 0/1 exit code) throws an incomplete-tagged error", async () => {
  const cache = createFsCache(
    path.join(cacheDir8, "incomplete"),
    () => 1000,
    86_400_000
  );
  const deadProject: Project = {
    gitRoot: "/dead",
    managers: [
      {
        configPath: "/dead/.npmrc",
        lockfilePath: "/dead/package-lock.json",
        manifestPath: "/dead/package.json",
        name: "npm",
        role: "primary",
      },
    ],
    root: "/dead",
  };
  const deps = {
    cache,
    digest: () => "dead-digest",
    now: () => 1000,
    readFile: () => "lock",
    run: () => ({ code: 2, stderr: "audit engine crashed", stdout: "" }),
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
  const cases: {
    name: "npm" | "pnpm" | "yarn" | "bun" | "uv";
    argv: string[];
  }[] = [
    { argv: ["npm", "audit", "--json"], name: "npm" },
    { argv: ["pnpm", "audit", "--json"], name: "pnpm" },
    { argv: ["yarn", "npm", "audit", "--json"], name: "yarn" },
    { argv: ["bun", "audit", "--json"], name: "bun" },
    {
      argv: ["uv", "audit", "--output-format", "json", "--frozen"],
      name: "uv",
    },
  ];
  await Promise.all(
    cases.map(async (row) => {
      const calls: string[][] = [];
      const cache = createFsCache(
        path.join(cacheDir8, `argv-${row.name}`),
        () => 1000,
        86_400_000
      );
      await auditAdvisories(
        {
          gitRoot: `/${row.name}`,
          managers: [
            {
              configPath: null,
              lockfilePath: `/${row.name}/lock`,
              manifestPath: `/${row.name}/manifest`,
              name: row.name,
              role: "primary",
            },
          ],
          root: `/${row.name}`,
        },
        loadPolicy({}),
        {
          cache,
          digest: () => `${row.name}-argv`,
          now: () => 1000,
          readFile: () => "lock",
          run: (argv) => {
            calls.push(argv);
            return { code: 0, stderr: "", stdout: "{}" };
          },
        }
      );
      expect(calls).toEqual([row.argv]);
    })
  );
});

test("enabledManagers omitting a live manager skips its native audit subprocess", async () => {
  const calls: string[][] = [];
  const cache = createFsCache(
    path.join(cacheDir8, "disabled"),
    () => 1000,
    86_400_000
  );
  const result = await auditAdvisories(
    {
      gitRoot: "/p",
      managers: [
        {
          configPath: "/p/pnpm-workspace.yaml",
          lockfilePath: "/p/pnpm-lock.yaml",
          manifestPath: "/p/package.json",
          name: "pnpm",
          role: "primary",
        },
      ],
      root: "/p",
    },
    loadPolicy({
      scanToml: 'enabledManagers = ["npm", "yarn", "bun", "uv"]\n',
    }),
    {
      cache,
      digest: () => "disabled-pnpm",
      now: () => 1000,
      readFile: () => "lock",
      run: (argv) => {
        calls.push(argv);
        return { code: 1, stderr: "", stdout: `{"advisories":{}}` };
      },
    }
  );
  expect(calls).toEqual([]);
  expect(result.findings).toEqual([]);
  expect(result.ranLive).toBe(false);
});

test("npm v7 vulnerabilities map fills package currentVersion and fixVersion", async () => {
  const cache = createFsCache(
    path.join(cacheDir8, "npm-v7"),
    () => 1000,
    86_400_000
  );
  const result = await auditAdvisories(
    {
      gitRoot: "/p",
      managers: [
        {
          configPath: "/p/.npmrc",
          lockfilePath: "/p/package-lock.json",
          manifestPath: "/p/package.json",
          name: "npm",
          role: "primary",
        },
      ],
      root: "/p",
    },
    loadPolicy({}),
    {
      cache,
      digest: () => "npm-v7",
      now: () => 1000,
      readFile: () => "lock",
      run: () => ({
        code: 1,
        stderr: "",
        stdout: JSON.stringify({
          auditReportVersion: 2,
          vulnerabilities: {
            "left-pad": {
              fixAvailable: { name: "left-pad", version: "1.3.0" },
              name: "left-pad",
              severity: "high",
              via: [
                {
                  github_advisory_id: "GHSA-v7",
                  severity: "high",
                  title: "left-pad v7 advisory",
                  version: "1.0.0",
                },
              ],
            },
          },
        }),
      }),
    }
  );
  const finding = result.findings.find((row) => row.kind === "advisory");
  expect(finding?.package).toBe("left-pad");
  expect(finding?.code).toBe("GHSA-v7");
  expect(finding?.currentVersion).toBe("1.0.0");
  expect(finding?.fixVersion).toBe("1.3.0");
});

test("cached advisory findings do not leak another repo path", async () => {
  const cache = createFsCache(
    path.join(cacheDir8, "path-leak"),
    () => 1000,
    86_400_000
  );
  const deps = {
    cache,
    digest: () => "shared-digest",
    now: () => 1000,
    readFile: () => "identical-lock",
    run: () => ({
      code: 1,
      stderr: "",
      stdout: JSON.stringify({
        advisories: {
          "1": {
            findings: [{ version: "1.0.0" }],
            github_advisory_id: "GHSA-share",
            module_name: "left-pad",
            severity: "high",
            title: "shared advisory",
          },
        },
      }),
    }),
  };
  const first = await auditAdvisories(
    {
      gitRoot: "/a",
      managers: [
        {
          configPath: "/a/.npmrc",
          lockfilePath: "/a/package-lock.json",
          manifestPath: "/a/package.json",
          name: "npm",
          role: "primary",
        },
      ],
      root: "/a",
    },
    loadPolicy({}),
    deps
  );
  expect(first.findings[0]?.path).toBe("/a/package-lock.json");

  const second = await auditAdvisories(
    {
      gitRoot: "/b",
      managers: [
        {
          configPath: "/b/.npmrc",
          lockfilePath: "/b/package-lock.json",
          manifestPath: "/b/package.json",
          name: "npm",
          role: "primary",
        },
      ],
      root: "/b",
    },
    loadPolicy({}),
    deps
  );
  expect(second.fromCache).toBe(true);
  expect(second.findings[0]?.path).toBe("/b/package-lock.json");
  expect(second.findings[0]?.path).not.toBe("/a/package-lock.json");
});

test("advisory runner throwing also surfaces an incomplete-tagged error", async () => {
  const cache = createFsCache(
    path.join(cacheDir8, "throws"),
    () => 1000,
    86_400_000
  );
  const throwsProject: Project = {
    gitRoot: "/throws",
    managers: [
      {
        configPath: "/throws/.npmrc",
        lockfilePath: "/throws/package-lock.json",
        manifestPath: "/throws/package.json",
        name: "npm",
        role: "primary",
      },
    ],
    root: "/throws",
  };
  const deps = {
    cache,
    digest: () => "throws-digest",
    now: () => 1000,
    readFile: () => "lock",
    run: () => {
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
