import { expect, test } from "bun:test";

import { applyAdvisories } from "../src/apply-advisories";
import { auditPath } from "../src/audit";
import type { Finding, PackageManager, Project } from "../src/domain";
import { createMemoryCache } from "../src/memory-cache";
import { loadPolicy } from "../src/policy";

const project: Project = {
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

const leftPadFinding: Finding = {
  code: "GHSA-left-pad",
  fixable: true,
  kind: "advisory",
  manager: "npm",
  message: "left-pad high advisory",
  package: "left-pad",
  path: "/p/package-lock.json",
  severity: "high",
};

test("apply advisories does not cross a major version", async () => {
  const ran: string[][] = [];
  const result = await applyAdvisories(project, [leftPadFinding], {
    allowMajors: false,
    currentVersions: { "left-pad": "1.0.0" },
    fixVersions: { "left-pad": "2.0.0" },
    run: (argv) => {
      ran.push(argv);
      return { code: 0, stderr: "", stdout: "" };
    },
  });
  expect(ran).toEqual([]);
  expect(result.skipped).toBe("nothing");
});

const projectFor = (name: PackageManager): Project => {
  const files: Record<
    PackageManager,
    { manifest: string; lock: string | null; config: string | null }
  > = {
    bun: {
      config: "/p/bunfig.toml",
      lock: "/p/bun.lock",
      manifest: "/p/package.json",
    },
    npm: {
      config: "/p/.npmrc",
      lock: "/p/package-lock.json",
      manifest: "/p/package.json",
    },
    pip: { config: null, lock: null, manifest: "/p/requirements.txt" },
    pipenv: { config: null, lock: "/p/Pipfile.lock", manifest: "/p/Pipfile" },
    pnpm: {
      config: "/p/pnpm-workspace.yaml",
      lock: "/p/pnpm-lock.yaml",
      manifest: "/p/package.json",
    },
    poetry: {
      config: null,
      lock: "/p/poetry.lock",
      manifest: "/p/pyproject.toml",
    },
    uv: {
      config: "/p/uv.toml",
      lock: "/p/uv.lock",
      manifest: "/p/pyproject.toml",
    },
    yarn: {
      config: "/p/.yarnrc.yml",
      lock: "/p/yarn.lock",
      manifest: "/p/package.json",
    },
  };
  const paths = files[name];
  return {
    gitRoot: "/p",
    managers: [
      {
        configPath: paths.config,
        lockfilePath: paths.lock,
        manifestPath: paths.manifest,
        name,
        role: "primary",
      },
    ],
    root: "/p",
  };
};

const findingFor = (name: PackageManager): Finding => {
  const [manager] = projectFor(name).managers;
  return {
    ...leftPadFinding,
    manager: name,
    path: manager?.lockfilePath ?? manager?.manifestPath ?? "",
  };
};

const okRun = (ran: string[][]) => (argv: string[]) => {
  ran.push(argv);
  return { code: 0, stderr: "", stdout: "" };
};

const memoryTree = (
  files: Record<string, string>,
  extraDirs: string[] = []
) => {
  const dirs = new Set<string>(["/", ...extraDirs]);
  const addDir = (dir: string) => {
    let current = dir;
    while (current && current !== "/") {
      dirs.add(current);
      current = current.slice(0, current.lastIndexOf("/")) || "/";
    }
  };
  for (const file of Object.keys(files)) {
    addDir(file.slice(0, file.lastIndexOf("/")) || "/");
  }
  for (const dir of extraDirs) {
    addDir(dir);
  }
  return {
    isDir: (filePath: string) => dirs.has(filePath),
    readDir: (dir: string) => {
      const prefix = dir.endsWith("/") ? dir : `${dir}/`;
      const names = new Set<string>();
      for (const entry of [...dirs, ...Object.keys(files)]) {
        if (!entry.startsWith(prefix)) {
          continue;
        }
        const [name] = entry.slice(prefix.length).split("/");
        if (name) {
          names.add(name);
        }
      }
      return [...names];
    },
    readFile: (filePath: string) => files[filePath] ?? null,
  };
};

test("apply advisories upgrades same major with npm install --save-exact", async () => {
  const ran: string[][] = [];
  const result = await applyAdvisories(projectFor("npm"), [findingFor("npm")], {
    allowMajors: false,
    currentVersions: { "left-pad": "1.0.0" },
    fixVersions: { "left-pad": "1.3.0" },
    run: okRun(ran),
  });
  expect(ran).toEqual([["npm", "install", "left-pad@1.3.0", "--save-exact"]]);
  expect(result.skipped).toBeNull();
});

test("apply advisories uses pnpm add for pnpm projects", async () => {
  const ran: string[][] = [];
  const result = await applyAdvisories(
    projectFor("pnpm"),
    [findingFor("pnpm")],
    {
      allowMajors: false,
      currentVersions: { "left-pad": "1.0.0" },
      fixVersions: { "left-pad": "1.3.0" },
      run: okRun(ran),
    }
  );
  expect(ran).toEqual([["pnpm", "add", "left-pad@1.3.0"]]);
  expect(result.skipped).toBeNull();
});

test("apply advisories uses uv lock --upgrade-package", async () => {
  const ran: string[][] = [];
  const result = await applyAdvisories(projectFor("uv"), [findingFor("uv")], {
    allowMajors: false,
    currentVersions: { "left-pad": "1.0.0" },
    fixVersions: { "left-pad": "1.3.0" },
    run: okRun(ran),
  });
  expect(ran).toEqual([["uv", "lock", "--upgrade-package", "left-pad"]]);
  expect(result.skipped).toBeNull();
});

test("apply advisories does not run an upgrade command for yarn or bun", async () => {
  await Promise.all(
    (["yarn", "bun"] as const).map(async (name) => {
      const ran: string[][] = [];
      const result = await applyAdvisories(
        projectFor(name),
        [findingFor(name)],
        {
          allowMajors: true,
          currentVersions: { "left-pad": "1.0.0" },
          fixVersions: { "left-pad": "1.3.0" },
          run: okRun(ran),
        }
      );
      expect(ran).toEqual([]);
      expect(result.skipped).toBe("nothing");
    })
  );
});

test("apply advisories does not write for non-uv python", async () => {
  await Promise.all(
    (["poetry", "pip", "pipenv"] as const).map(async (name) => {
      const ran: string[][] = [];
      const result = await applyAdvisories(
        projectFor(name),
        [findingFor(name)],
        {
          allowMajors: true,
          currentVersions: { "left-pad": "1.0.0" },
          fixVersions: { "left-pad": "1.3.0" },
          run: okRun(ran),
        }
      );
      expect(ran).toEqual([]);
      expect(result.skipped).toBe("nothing");
    })
  );
});

test("apply advisories crosses a major when allowMajors is true", async () => {
  const ran: string[][] = [];
  const result = await applyAdvisories(projectFor("npm"), [findingFor("npm")], {
    allowMajors: true,
    currentVersions: { "left-pad": "1.0.0" },
    fixVersions: { "left-pad": "2.0.0" },
    run: okRun(ran),
  });
  expect(ran).toEqual([["npm", "install", "left-pad@2.0.0", "--save-exact"]]);
  expect(result.skipped).toBeNull();
});

test("apply advisories crosses a major when policy preset is strict", async () => {
  const ran: string[][] = [];
  const result = await applyAdvisories(projectFor("npm"), [findingFor("npm")], {
    allowMajors: false,
    currentVersions: { "left-pad": "1.0.0" },
    fixVersions: { "left-pad": "2.0.0" },
    policy: loadPolicy({ flags: { preset: "strict" } }),
    run: okRun(ran),
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
        currentVersion: "1.0.0",
        fixVersion: "1.3.0",
        package: "left-pad",
      },
    ],
    {
      allowMajors: false,
      currentVersions: {},
      fixVersions: {},
      run: okRun(ran),
    }
  );
  expect(ran).toEqual([["npm", "install", "left-pad@1.3.0", "--save-exact"]]);
  expect(result.skipped).toBeNull();
});

test("apply skips a package when current version is unknown", async () => {
  const ran: string[][] = [];
  const result = await applyAdvisories(
    projectFor("npm"),
    [
      {
        ...findingFor("npm"),
        fixVersion: "1.3.0",
        package: "left-pad",
      },
    ],
    {
      allowMajors: false,
      currentVersions: {},
      fixVersions: {},
      run: okRun(ran),
    }
  );
  expect(ran).toEqual([]);
  expect(result.skipped).toBe("nothing");
});

test("apply uses the highest same-major fix across findings for one package", async () => {
  const ran: string[][] = [];
  const result = await applyAdvisories(
    projectFor("npm"),
    [
      {
        ...findingFor("npm"),
        currentVersion: "1.0.0",
        fixVersion: "1.2.0",
        package: "left-pad",
      },
      {
        ...findingFor("npm"),
        currentVersion: "1.0.0",
        fixVersion: "1.5.0",
        package: "left-pad",
      },
      {
        ...findingFor("npm"),
        currentVersion: "1.0.0",
        fixVersion: "2.0.0",
        package: "left-pad",
      },
    ],
    {
      allowMajors: false,
      currentVersions: {},
      fixVersions: {},
      run: okRun(ran),
    }
  );
  expect(ran).toEqual([["npm", "install", "left-pad@1.5.0", "--save-exact"]]);
  expect(result.skipped).toBeNull();
});

test("apply prefers a release fix over a prerelease of the same version", async () => {
  const ran: string[][] = [];
  const result = await applyAdvisories(
    projectFor("npm"),
    [
      {
        ...findingFor("npm"),
        currentVersion: "1.0.0",
        fixVersion: "1.5.0-beta.1",
        package: "left-pad",
      },
      {
        ...findingFor("npm"),
        currentVersion: "1.0.0",
        fixVersion: "1.5.0",
        package: "left-pad",
      },
    ],
    {
      allowMajors: false,
      currentVersions: {},
      fixVersions: {},
      run: okRun(ran),
    }
  );
  expect(ran).toEqual([["npm", "install", "left-pad@1.5.0", "--save-exact"]]);
  expect(result.skipped).toBeNull();
});

test("apply uses the highest fix including majors when allowMajors is true", async () => {
  const ran: string[][] = [];
  const result = await applyAdvisories(
    projectFor("npm"),
    [
      {
        ...findingFor("npm"),
        currentVersion: "1.0.0",
        fixVersion: "1.5.0",
        package: "left-pad",
      },
      {
        ...findingFor("npm"),
        currentVersion: "1.0.0",
        fixVersion: "2.1.0",
        package: "left-pad",
      },
    ],
    {
      allowMajors: true,
      currentVersions: {},
      fixVersions: {},
      run: okRun(ran),
    }
  );
  expect(ran).toEqual([["npm", "install", "left-pad@2.1.0", "--save-exact"]]);
  expect(result.skipped).toBeNull();
});

test("apply advisories matches package identity not a message substring", async () => {
  const ran: string[][] = [];
  await applyAdvisories(
    projectFor("npm"),
    [
      {
        ...findingFor("npm"),
        currentVersion: "1.0.0",
        fixVersion: "1.3.0",
        message: "left-pad high advisory",
        package: "left-pad",
      },
    ],
    {
      allowMajors: false,
      currentVersions: { pad: "1.0.0" },
      fixVersions: { pad: "1.3.0" },
      run: okRun(ran),
    }
  );
  expect(ran).toEqual([["npm", "install", "left-pad@1.3.0", "--save-exact"]]);
  expect(ran.some((argv) => argv.includes("pad@1.3.0"))).toBe(false);
});

test("apply-advisories without version maps upgrades from advisory JSON fields", async () => {
  const files: Record<string, string> = {
    "/p/.npmrc": CLEAN_NPMRC,
    "/p/package-lock.json": `{"lockfileVersion":3}`,
    "/p/package.json": `{"name":"x"}`,
  };
  const ran: string[][] = [];
  const result = await auditPath("/p", {
    allowMajors: false,
    apply: false,
    applyAdvisories: true,
    concurrency: 1,
    deps: {
      ...memoryTree(files, ["/p/.git"]),
      cache: createMemoryCache(() => 1000, 86_400_000),
      now: () => 1000,
      run: (argv) => {
        ran.push(argv);
        if (argv.includes("audit")) {
          return {
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
          };
        }
        return { code: 0, stderr: "", stdout: "" };
      },
      which: () => "/usr/bin/npm",
    },
    interactive: false,
    policy: loadPolicy({}),
  });
  const finding = result.projects[0]?.findings.find(
    (row) => row.kind === "advisory"
  );
  expect(finding?.package).toBe("left-pad");
  expect(finding?.currentVersion).toBe("1.0.0");
  expect(finding?.fixVersion).toBe("1.3.0");
  expect(ran).toContainEqual([
    "npm",
    "install",
    "left-pad@1.3.0",
    "--save-exact",
  ]);
});

const LEFT_PAD_AUDIT_JSON = JSON.stringify({
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
});

test("--apply --apply-advisories still applies advisories after the settings write dirties the tree", async () => {
  const files: Record<string, string> = {
    "/p/.npmrc":
      "audit=true\naudit-level=high\nmin-release-age=7\nregistry=https://registry.npmjs.org/\n",
    "/p/package-lock.json": `{"lockfileVersion":3}`,
    "/p/package.json": `{"name":"x","packageManager":"npm@10.9.0"}`,
  };
  let tree: "clean" | "dirty" = "clean";
  const ran: string[][] = [];
  const result = await auditPath("/p", {
    allowMajors: false,
    apply: true,
    applyAdvisories: true,
    commit: false,
    concurrency: 1,
    deps: {
      ...memoryTree(files, ["/p/.git"]),
      cache: createMemoryCache(() => 1000, 86_400_000),
      gitStatus: () => tree,
      now: () => 1000,
      run: (argv) => {
        ran.push(argv);
        if (argv.includes("audit")) {
          return { code: 1, stderr: "", stdout: LEFT_PAD_AUDIT_JSON };
        }
        return { code: 0, stderr: "", stdout: "" };
      },
      which: () => "/usr/bin/npm",
      writeFile: (p, b) => {
        files[p] = b;
        tree = "dirty";
      },
    },
    force: false,
    interactive: false,
    policy: loadPolicy({}),
  });
  expect(files["/p/.npmrc"]).toContain("ignore-scripts=true");
  expect(ran).toContainEqual([
    "npm",
    "install",
    "left-pad@1.3.0",
    "--save-exact",
  ]);
  expect(result.exitCode).not.toBe(2);
});

test("interactive both applies advisories after the settings write dirties the tree", async () => {
  const files: Record<string, string> = {
    "/p/.npmrc":
      "audit=true\naudit-level=high\nmin-release-age=7\nregistry=https://registry.npmjs.org/\n",
    "/p/package-lock.json": `{"lockfileVersion":3}`,
    "/p/package.json": `{"name":"x","packageManager":"npm@10.9.0"}`,
  };
  let tree: "clean" | "dirty" = "clean";
  const ran: string[][] = [];
  const result = await auditPath("/p", {
    allowMajors: false,
    apply: false,
    applyAdvisories: false,
    commit: false,
    concurrency: 1,
    deps: {
      ...memoryTree(files, ["/p/.git"]),
      cache: createMemoryCache(() => 1000, 86_400_000),
      gitStatus: () => tree,
      now: () => 1000,
      prompt: () => "both" as const,
      run: (argv) => {
        ran.push(argv);
        if (argv.includes("audit")) {
          return { code: 1, stderr: "", stdout: LEFT_PAD_AUDIT_JSON };
        }
        return { code: 0, stderr: "", stdout: "" };
      },
      which: () => "/usr/bin/npm",
      writeFile: (p, b) => {
        files[p] = b;
        tree = "dirty";
      },
    },
    force: false,
    interactive: true,
    policy: loadPolicy({}),
  });
  expect(files["/p/.npmrc"]).toContain("ignore-scripts=true");
  expect(ran).toContainEqual([
    "npm",
    "install",
    "left-pad@1.3.0",
    "--save-exact",
  ]);
  expect(result.exitCode).not.toBe(2);
});

test("interactive advisories choice allows a major upgrade", async () => {
  const files: Record<string, string> = {
    "/p/.npmrc": CLEAN_NPMRC,
    "/p/package-lock.json": `{"lockfileVersion":3}`,
    "/p/package.json": `{"name":"x"}`,
  };
  const ran: string[][] = [];
  await auditPath("/p", {
    allowMajors: false,
    apply: false,
    applyAdvisories: false,
    concurrency: 1,
    deps: {
      ...memoryTree(files, ["/p/.git"]),
      cache: createMemoryCache(() => 1000, 86_400_000),
      gitStatus: () => "clean" as const,
      now: () => 1000,
      prompt: () => "advisories" as const,
      run: (argv) => {
        ran.push(argv);
        if (argv.includes("audit")) {
          return {
            code: 1,
            stderr: "",
            stdout: JSON.stringify({
              advisories: {
                "1": {
                  findings: [{ version: "1.0.0" }],
                  fixAvailable: { name: "left-pad", version: "2.0.0" },
                  github_advisory_id: "GHSA-left-pad",
                  module_name: "left-pad",
                  severity: "high",
                  title: "left-pad high advisory",
                },
              },
            }),
          };
        }
        return { code: 0, stderr: "", stdout: "" };
      },
      which: () => "/usr/bin/npm",
    },
    interactive: true,
    policy: loadPolicy({}),
  });
  expect(ran).toContainEqual([
    "npm",
    "install",
    "left-pad@2.0.0",
    "--save-exact",
  ]);
});

test("audit concurrency pools advisory runs and keeps apply serial", async () => {
  const files: Record<string, string> = {
    "/repo/a/.npmrc": CLEAN_NPMRC,
    "/repo/a/package-lock.json": `{"a":1}`,
    "/repo/a/package.json": `{"name":"a"}`,
    "/repo/b/.npmrc": CLEAN_NPMRC,
    "/repo/b/package-lock.json": `{"b":1}`,
    "/repo/b/package.json": `{"name":"b"}`,
    "/repo/c/.npmrc": CLEAN_NPMRC,
    "/repo/c/package-lock.json": `{"c":1}`,
    "/repo/c/package.json": `{"name":"c"}`,
  };
  let auditInFlight = 0;
  let maxAudit = 0;
  let applyInFlight = 0;
  let maxApply = 0;
  const result = await auditPath("/repo", {
    allowMajors: false,
    apply: false,
    applyAdvisories: true,
    concurrency: 2,
    deps: {
      ...memoryTree(files, ["/repo/.git"]),
      cache: createMemoryCache(() => 1000, 86_400_000),
      currentVersions: { "left-pad": "1.0.0" },
      fixVersions: { "left-pad": "1.3.0" },
      now: () => 1000,
      run: async (argv) => {
        if (argv.includes("audit")) {
          auditInFlight += 1;
          maxAudit = Math.max(maxAudit, auditInFlight);
          await Bun.sleep(30);
          auditInFlight -= 1;
          return {
            code: 1,
            stderr: "",
            stdout: JSON.stringify({
              advisories: {
                "1": {
                  findings: [{ version: "1.0.0" }],
                  github_advisory_id: "GHSA-left-pad",
                  module_name: "left-pad",
                  severity: "high",
                  title: "left-pad high advisory",
                },
              },
            }),
          };
        }
        applyInFlight += 1;
        maxApply = Math.max(maxApply, applyInFlight);
        await Bun.sleep(10);
        applyInFlight -= 1;
        return { code: 0, stderr: "", stdout: "" };
      },
      which: () => "/usr/bin/npm",
    },
    interactive: false,
    policy: loadPolicy({}),
  });
  expect(result.projects).toHaveLength(3);
  expect(maxAudit).toBeGreaterThan(1);
  expect(maxApply).toBeLessThanOrEqual(1);
});
