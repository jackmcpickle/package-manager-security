import { afterAll, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { applyAdvisories } from "../src/apply-advisories";
import { auditPath } from "../src/audit";
import { createFsCache } from "../src/cache";
import type { Finding, PackageManager, Project } from "../src/domain";
import { loadPolicy } from "../src/policy";

const cacheDir = mkdtempSync(join(tmpdir(), "pmsec-apply-adv-"));
afterAll(() => {
  rmSync(cacheDir, { recursive: true, force: true });
});

const project: Project = {
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

const leftPadFinding: Finding = {
  kind: "advisory",
  code: "GHSA-left-pad",
  message: "left-pad high advisory",
  severity: "high",
  path: "/p/package-lock.json",
  fixable: true,
  manager: "npm",
  package: "left-pad",
};

test("apply advisories does not cross a major version", async () => {
  const ran: string[][] = [];
  const result = await applyAdvisories(project, [leftPadFinding], {
    run: async (argv) => {
      ran.push(argv);
      return { code: 0, stdout: "", stderr: "" };
    },
    allowMajors: false,
    currentVersions: { "left-pad": "1.0.0" },
    fixVersions: { "left-pad": "2.0.0" },
  });
  expect(ran).toEqual([]);
  expect(result.skipped).toBe("nothing");
});

function projectFor(name: PackageManager): Project {
  const files: Record<PackageManager, { manifest: string; lock: string | null; config: string | null }> = {
    npm: { manifest: "/p/package.json", lock: "/p/package-lock.json", config: "/p/.npmrc" },
    pnpm: { manifest: "/p/package.json", lock: "/p/pnpm-lock.yaml", config: "/p/pnpm-workspace.yaml" },
    yarn: { manifest: "/p/package.json", lock: "/p/yarn.lock", config: "/p/.yarnrc.yml" },
    bun: { manifest: "/p/package.json", lock: "/p/bun.lock", config: "/p/bunfig.toml" },
    uv: { manifest: "/p/pyproject.toml", lock: "/p/uv.lock", config: "/p/uv.toml" },
    poetry: { manifest: "/p/pyproject.toml", lock: "/p/poetry.lock", config: null },
    pip: { manifest: "/p/requirements.txt", lock: null, config: null },
    pipenv: { manifest: "/p/Pipfile", lock: "/p/Pipfile.lock", config: null },
  };
  const paths = files[name];
  return {
    root: "/p",
    gitRoot: "/p",
    managers: [
      {
        name,
        role: "primary",
        manifestPath: paths.manifest,
        lockfilePath: paths.lock,
        configPath: paths.config,
      },
    ],
  };
}

function findingFor(name: PackageManager): Finding {
  return {
    ...leftPadFinding,
    manager: name,
    path: projectFor(name).managers[0]!.lockfilePath ?? projectFor(name).managers[0]!.manifestPath,
  };
}

function okRun(ran: string[][]) {
  return async (argv: string[]) => {
    ran.push(argv);
    return { code: 0, stdout: "", stderr: "" };
  };
}

test("apply advisories upgrades same major with npm install --save-exact", async () => {
  const ran: string[][] = [];
  const result = await applyAdvisories(projectFor("npm"), [findingFor("npm")], {
    run: okRun(ran),
    allowMajors: false,
    currentVersions: { "left-pad": "1.0.0" },
    fixVersions: { "left-pad": "1.3.0" },
  });
  expect(ran).toEqual([["npm", "install", "left-pad@1.3.0", "--save-exact"]]);
  expect(result.skipped).toBeNull();
});

test("apply advisories uses pnpm add for pnpm projects", async () => {
  const ran: string[][] = [];
  const result = await applyAdvisories(projectFor("pnpm"), [findingFor("pnpm")], {
    run: okRun(ran),
    allowMajors: false,
    currentVersions: { "left-pad": "1.0.0" },
    fixVersions: { "left-pad": "1.3.0" },
  });
  expect(ran).toEqual([["pnpm", "add", "left-pad@1.3.0"]]);
  expect(result.skipped).toBeNull();
});

test("apply advisories uses uv lock --upgrade-package", async () => {
  const ran: string[][] = [];
  const result = await applyAdvisories(projectFor("uv"), [findingFor("uv")], {
    run: okRun(ran),
    allowMajors: false,
    currentVersions: { "left-pad": "1.0.0" },
    fixVersions: { "left-pad": "1.3.0" },
  });
  expect(ran).toEqual([["uv", "lock", "--upgrade-package", "left-pad"]]);
  expect(result.skipped).toBeNull();
});

test("apply advisories does not write for non-uv python", async () => {
  for (const name of ["poetry", "pip", "pipenv"] as const) {
    const ran: string[][] = [];
    const result = await applyAdvisories(projectFor(name), [findingFor(name)], {
      run: okRun(ran),
      allowMajors: true,
      currentVersions: { "left-pad": "1.0.0" },
      fixVersions: { "left-pad": "1.3.0" },
    });
    expect(ran).toEqual([]);
    expect(result.skipped).toBe("nothing");
  }
});

test("apply advisories crosses a major when allowMajors is true", async () => {
  const ran: string[][] = [];
  const result = await applyAdvisories(projectFor("npm"), [findingFor("npm")], {
    run: okRun(ran),
    allowMajors: true,
    currentVersions: { "left-pad": "1.0.0" },
    fixVersions: { "left-pad": "2.0.0" },
  });
  expect(ran).toEqual([["npm", "install", "left-pad@2.0.0", "--save-exact"]]);
  expect(result.skipped).toBeNull();
});

test("apply advisories crosses a major when policy preset is strict", async () => {
  const ran: string[][] = [];
  const result = await applyAdvisories(projectFor("npm"), [findingFor("npm")], {
    run: okRun(ran),
    allowMajors: false,
    currentVersions: { "left-pad": "1.0.0" },
    fixVersions: { "left-pad": "2.0.0" },
    policy: loadPolicy({ flags: { preset: "strict" } }),
  });
  expect(ran).toEqual([["npm", "install", "left-pad@2.0.0", "--save-exact"]]);
  expect(result.skipped).toBeNull();
});

const CLEAN_NPMRC =
  "ignore-scripts=true\naudit=true\naudit-level=high\nmin-release-age=7\nregistry=https://registry.npmjs.org/\n";

test("apply advisories uses package currentVersion and fixVersion on the finding", async () => {
  const ran: string[][] = [];
  const result = await applyAdvisories(
    projectFor("npm"),
    [
      {
        ...findingFor("npm"),
        package: "left-pad",
        currentVersion: "1.0.0",
        fixVersion: "1.3.0",
      },
    ],
    {
      run: okRun(ran),
      allowMajors: false,
      currentVersions: {},
      fixVersions: {},
    },
  );
  expect(ran).toEqual([["npm", "install", "left-pad@1.3.0", "--save-exact"]]);
  expect(result.skipped).toBeNull();
});

test("apply advisories matches package identity not a message substring", async () => {
  const ran: string[][] = [];
  await applyAdvisories(
    projectFor("npm"),
    [
      {
        ...findingFor("npm"),
        message: "left-pad high advisory",
        package: "left-pad",
        currentVersion: "1.0.0",
        fixVersion: "1.3.0",
      },
    ],
    {
      run: okRun(ran),
      allowMajors: false,
      currentVersions: { pad: "1.0.0" },
      fixVersions: { pad: "1.3.0" },
    },
  );
  expect(ran).toEqual([["npm", "install", "left-pad@1.3.0", "--save-exact"]]);
  expect(ran.some((argv) => argv.includes("pad@1.3.0"))).toBe(false);
});

test("apply-advisories without version maps upgrades from advisory JSON fields", async () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x"}`,
    "/p/package-lock.json": `{"lockfileVersion":3}`,
    "/p/.npmrc": CLEAN_NPMRC,
  };
  const ran: string[][] = [];
  const result = await auditPath("/p", {
    policy: loadPolicy({}),
    apply: false,
    applyAdvisories: true,
    interactive: false,
    concurrency: 1,
    allowMajors: false,
    deps: {
      ...memoryTree(files, ["/p/.git"]),
      which: () => "/usr/bin/npm",
      run: async (argv) => {
        ran.push(argv);
        if (argv.includes("audit")) {
          return {
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
          };
        }
        return { code: 0, stdout: "", stderr: "" };
      },
      cache: createFsCache(join(cacheDir, "from-findings"), () => 1_000, 86_400_000),
      now: () => 1_000,
    },
  });
  const finding = result.projects[0]?.findings.find((row) => row.kind === "advisory");
  expect(finding?.package).toBe("left-pad");
  expect(finding?.currentVersion).toBe("1.0.0");
  expect(finding?.fixVersion).toBe("1.3.0");
  expect(ran).toContainEqual(["npm", "install", "left-pad@1.3.0", "--save-exact"]);
});

test("interactive advisories choice allows a major upgrade", async () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x"}`,
    "/p/package-lock.json": `{"lockfileVersion":3}`,
    "/p/.npmrc": CLEAN_NPMRC,
  };
  const ran: string[][] = [];
  await auditPath("/p", {
    policy: loadPolicy({}),
    apply: false,
    applyAdvisories: false,
    interactive: true,
    concurrency: 1,
    allowMajors: false,
    deps: {
      ...memoryTree(files, ["/p/.git"]),
      which: () => "/usr/bin/npm",
      run: async (argv) => {
        ran.push(argv);
        if (argv.includes("audit")) {
          return {
            code: 1,
            stdout: JSON.stringify({
              advisories: {
                "1": {
                  module_name: "left-pad",
                  severity: "high",
                  github_advisory_id: "GHSA-left-pad",
                  title: "left-pad high advisory",
                  findings: [{ version: "1.0.0" }],
                  fixAvailable: { name: "left-pad", version: "2.0.0" },
                },
              },
            }),
            stderr: "",
          };
        }
        return { code: 0, stdout: "", stderr: "" };
      },
      cache: createFsCache(join(cacheDir, "interactive-major"), () => 1_000, 86_400_000),
      now: () => 1_000,
      gitStatus: () => "clean" as const,
      prompt: async () => "advisories",
    },
  });
  expect(ran).toContainEqual(["npm", "install", "left-pad@2.0.0", "--save-exact"]);
});

function memoryTree(files: Record<string, string>, extraDirs: string[] = []) {
  const dirs = new Set<string>(["/", ...extraDirs]);
  const addDir = (dir: string) => {
    let current = dir;
    while (current && current !== "/") {
      dirs.add(current);
      current = current.slice(0, current.lastIndexOf("/")) || "/";
    }
  };
  for (const file of Object.keys(files)) addDir(file.slice(0, file.lastIndexOf("/")) || "/");
  for (const dir of extraDirs) addDir(dir);
  return {
    readFile: (path: string) => files[path] ?? null,
    readDir: (dir: string) => {
      const prefix = dir.endsWith("/") ? dir : `${dir}/`;
      const names = new Set<string>();
      for (const path of [...dirs, ...Object.keys(files)]) {
        if (!path.startsWith(prefix)) continue;
        const name = path.slice(prefix.length).split("/")[0];
        if (name) names.add(name);
      }
      return [...names];
    },
    isDir: (path: string) => dirs.has(path),
  };
}

test("audit concurrency pools advisory runs and keeps apply serial", async () => {
  const files: Record<string, string> = {
    "/repo/a/package.json": `{"name":"a"}`,
    "/repo/a/package-lock.json": `{"a":1}`,
    "/repo/a/.npmrc": CLEAN_NPMRC,
    "/repo/b/package.json": `{"name":"b"}`,
    "/repo/b/package-lock.json": `{"b":1}`,
    "/repo/b/.npmrc": CLEAN_NPMRC,
    "/repo/c/package.json": `{"name":"c"}`,
    "/repo/c/package-lock.json": `{"c":1}`,
    "/repo/c/.npmrc": CLEAN_NPMRC,
  };
  let auditInFlight = 0;
  let maxAudit = 0;
  let applyInFlight = 0;
  let maxApply = 0;
  const result = await auditPath("/repo", {
    policy: loadPolicy({}),
    apply: false,
    applyAdvisories: true,
    interactive: false,
    concurrency: 2,
    allowMajors: false,
    deps: {
      ...memoryTree(files, ["/repo/.git"]),
      which: () => "/usr/bin/npm",
      run: async (argv) => {
        if (argv.includes("audit")) {
          auditInFlight += 1;
          maxAudit = Math.max(maxAudit, auditInFlight);
          await Bun.sleep(30);
          auditInFlight -= 1;
          return {
            code: 1,
            stdout: JSON.stringify({
              advisories: {
                "1": {
                  module_name: "left-pad",
                  severity: "high",
                  github_advisory_id: "GHSA-left-pad",
                  title: "left-pad high advisory",
                  findings: [{ version: "1.0.0" }],
                },
              },
            }),
            stderr: "",
          };
        }
        applyInFlight += 1;
        maxApply = Math.max(maxApply, applyInFlight);
        await Bun.sleep(10);
        applyInFlight -= 1;
        return { code: 0, stdout: "", stderr: "" };
      },
      cache: createFsCache(cacheDir, () => 1_000, 86_400_000),
      now: () => 1_000,
      currentVersions: { "left-pad": "1.0.0" },
      fixVersions: { "left-pad": "1.3.0" },
    },
  });
  expect(result.projects).toHaveLength(3);
  expect(maxAudit).toBeGreaterThan(1);
  expect(maxApply).toBeLessThanOrEqual(1);
});
