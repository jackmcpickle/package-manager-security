import { expect, test } from "bun:test";

import { applySettings } from "../src/apply-settings";
import { auditPath } from "../src/audit";
import type { Finding, Project } from "../src/domain";
import { loadPolicy } from "../src/policy";
import { auditSettings } from "../src/settings";

const npmProject = (root: string): Project => ({
  gitRoot: root,
  managers: [
    {
      configPath: `${root}/.npmrc`,
      lockfilePath: `${root}/package-lock.json`,
      manifestPath: `${root}/package.json`,
      name: "npm",
      role: "primary",
    },
  ],
  root,
});

test("apply writes ignore-scripts to .npmrc on a clean tree", () => {
  const files: Record<string, string> = {
    "/p/.npmrc": `registry=https://registry.npmjs.org/\n`,
    "/p/package-lock.json": `{}`,
    "/p/package.json": `{"name":"x"}`,
  };
  const project = npmProject("/p");
  const findings = auditSettings(project, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  const result = applySettings(project, findings, loadPolicy({}), {
    commit: false,
    force: false,
    gitStatus: () => "clean",
    readFile: (p) => files[p] ?? null,
    writeFile: (p, b) => {
      files[p] = b;
    },
  });
  expect(result.skipped).toBeNull();
  expect(files["/p/.npmrc"]).toContain("ignore-scripts=true");
});

test("apply skips a dirty tree without force", () => {
  const project = npmProject("/p");
  const findings = auditSettings(project, loadPolicy({}), {
    readFile: () => null,
  });
  const result = applySettings(project, findings, loadPolicy({}), {
    commit: false,
    force: false,
    gitStatus: () => "dirty",
    readFile: () => null,
    writeFile: () => {
      throw new Error("must not write");
    },
  });
  expect(result.skipped).toBe("dirty");
});

test("apply writes pnpm keys to pnpm-workspace.yaml not .npmrc", () => {
  const files: Record<string, string> = {
    "/p/.npmrc": "registry=https://registry.npmjs.org/\n",
    "/p/package.json": `{"name":"x","packageManager":"pnpm@10.0.0"}`,
    "/p/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
    "/p/pnpm-workspace.yaml": "packages:\n  - '.'\n",
  };
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
  const findings = auditSettings(project, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  const result = applySettings(project, findings, loadPolicy({}), {
    commit: false,
    force: false,
    gitStatus: () => "clean",
    readFile: (p) => files[p] ?? null,
    writeFile: (p, b) => {
      files[p] = b;
    },
  });
  expect(result.skipped).toBeNull();
  expect(result.written).toContain("/p/pnpm-workspace.yaml");
  expect(result.written).not.toContain("/p/.npmrc");
  expect(files["/p/.npmrc"]).toBe("registry=https://registry.npmjs.org/\n");
});

test("apply writes pnpm minimumReleaseAge as 10080 minutes for standard", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x","packageManager":"pnpm@10.0.0"}`,
    "/p/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
    "/p/pnpm-workspace.yaml": "packages:\n  - '.'\n",
  };
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
  const findings = auditSettings(project, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  const result = applySettings(project, findings, loadPolicy({}), {
    commit: false,
    force: false,
    gitStatus: () => "clean",
    readFile: (p) => files[p] ?? null,
    writeFile: (p, b) => {
      files[p] = b;
    },
  });
  expect(result.skipped).toBeNull();
  expect(files["/p/pnpm-workspace.yaml"]).toContain("minimumReleaseAge: 10080");
});

test("apply does not write leftover lockfiles or ~/.npmrc", () => {
  const files: Record<string, string> = {
    "/home/user/.npmrc": "ignore-scripts=false\n",
    "/p/package-lock.json": "{}",
    "/p/package.json": `{"name":"x","packageManager":"pnpm@10.0.0"}`,
    "/p/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
  };
  const leftover: Finding = {
    code: "lockfile.leftover",
    fixable: false,
    kind: "leftover-lockfile",
    manager: "npm",
    message: "Leftover npm lockfile is not an apply target",
    path: "/p/package-lock.json",
    severity: "high",
  };
  const home: Finding = {
    code: "scripts.unrestricted",
    fixable: true,
    kind: "settings",
    manager: "npm",
    message: "npm ignore-scripts must be true",
    path: "~/.npmrc",
    severity: "high",
  };
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
      {
        configPath: "~/.npmrc",
        lockfilePath: "/p/package-lock.json",
        manifestPath: "/p/package.json",
        name: "npm",
        role: "leftover",
      },
    ],
    root: "/p",
  };
  const result = applySettings(project, [leftover, home], loadPolicy({}), {
    commit: false,
    force: false,
    gitStatus: () => "clean",
    readFile: (p) => files[p] ?? null,
    writeFile: (p, b) => {
      files[p] = b;
    },
  });
  expect(files["/p/package-lock.json"]).toBe("{}");
  expect(files["~/.npmrc"]).toBeUndefined();
  expect(files["/home/user/.npmrc"]).toBe("ignore-scripts=false\n");
  expect(result.written).not.toContain("/p/package-lock.json");
  expect(result.written).not.toContain("~/.npmrc");
});

test("auditPath maps apply skipped dirty to exit 2", async () => {
  const files: Record<string, string> = {
    "/p/.npmrc": `registry=https://registry.npmjs.org/\n`,
    "/p/package-lock.json": `{}`,
    "/p/package.json": `{"name":"x"}`,
  };
  const result = await auditPath("/p", {
    apply: true,
    applyAdvisories: false,
    commit: false,
    concurrency: 4,
    deps: {
      gitStatus: () => "dirty",
      isDir: (p) => p === "/p" || p === "/p/.git",
      readDir: (dir) => {
        if (dir === "/p") {
          return ["package.json", "package-lock.json", ".npmrc", ".git"];
        }
        return [];
      },
      readFile: (p) => files[p] ?? null,
      run: () => ({ code: 0, stderr: "", stdout: `{"advisories":{}}` }),
      which: () => "/usr/bin/npm",
      writeFile: () => {
        throw new Error("must not write");
      },
    },
    force: false,
    interactive: false,
    policy: loadPolicy({}),
  });
  expect(result.exitCode).toBe(2);
});

test("auditPath apply on a clean tree writes settings and is not the stub exit 2", async () => {
  const files: Record<string, string> = {
    "/p/.npmrc": `registry=https://registry.npmjs.org/\n`,
    "/p/package-lock.json": `{}`,
    "/p/package.json": `{"name":"x"}`,
  };
  const result = await auditPath("/p", {
    apply: true,
    applyAdvisories: false,
    commit: false,
    concurrency: 4,
    deps: {
      gitStatus: () => "clean",
      isDir: (p) => p === "/p" || p === "/p/.git",
      readDir: (dir) => {
        if (dir === "/p") {
          return ["package.json", "package-lock.json", ".npmrc", ".git"];
        }
        return [];
      },
      readFile: (p) => files[p] ?? null,
      run: () => ({ code: 0, stderr: "", stdout: `{"advisories":{}}` }),
      which: () => "/usr/bin/npm",
      writeFile: (p, b) => {
        files[p] = b;
      },
    },
    force: false,
    interactive: false,
    policy: loadPolicy({}),
  });
  expect(files["/p/.npmrc"]).toContain("ignore-scripts=true");
  expect(result.exitCode).not.toBe(2);
});

test("two npm/pnpm roots sharing a gitRoot both get written without force", async () => {
  const files: Record<string, string> = {
    "/repo/a/.npmrc": `registry=https://registry.npmjs.org/\n`,
    "/repo/a/package-lock.json": `{}`,
    "/repo/a/package.json": `{"name":"a"}`,
    "/repo/b/package.json": `{"name":"b","packageManager":"pnpm@10.0.0"}`,
    "/repo/b/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
    "/repo/b/pnpm-workspace.yaml": "packages:\n  - '.'\n",
  };
  let tree: "clean" | "dirty" = "clean";
  const commits: { root: string; files: string[] }[] = [];
  const result = await auditPath("/repo", {
    apply: true,
    applyAdvisories: false,
    commit: true,
    concurrency: 4,
    deps: {
      gitCommit: (root, _message, written) => {
        commits.push({ files: written, root });
        return true;
      },
      gitStatus: () => tree,
      isDir: (p) =>
        p === "/repo" ||
        p === "/repo/.git" ||
        p === "/repo/a" ||
        p === "/repo/b",
      readDir: (dir) => {
        if (dir === "/repo") {
          return [".git", "a", "b"];
        }
        if (dir === "/repo/a") {
          return ["package.json", "package-lock.json", ".npmrc"];
        }
        if (dir === "/repo/b") {
          return ["package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml"];
        }
        return [];
      },
      readFile: (p) => files[p] ?? null,
      run: () => ({ code: 0, stderr: "", stdout: `{"advisories":{}}` }),
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
  expect(files["/repo/a/.npmrc"]).toContain("ignore-scripts=true");
  expect(files["/repo/b/pnpm-workspace.yaml"]).toContain("allowBuilds: {}");
  expect(files["/repo/b/pnpm-workspace.yaml"]).toContain(
    "minimumReleaseAge: 10080"
  );
  expect(commits).toEqual([
    {
      files: ["/repo/a/.npmrc", "/repo/b/pnpm-workspace.yaml"],
      root: "/repo",
    },
  ]);
  expect(result.exitCode).not.toBe(2);
});

test("apply skips a not-git tree without force", () => {
  const files: Record<string, string> = {
    "/p/.npmrc": `registry=https://registry.npmjs.org/\n`,
    "/p/package-lock.json": `{}`,
    "/p/package.json": `{"name":"x"}`,
  };
  const project = npmProject("/p");
  const findings = auditSettings(project, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  const result = applySettings(project, findings, loadPolicy({}), {
    commit: false,
    force: false,
    gitStatus: () => "not-git",
    readFile: (p) => files[p] ?? null,
    writeFile: () => {
      throw new Error("must not write");
    },
  });
  expect(result.skipped).toBe("dirty");
  expect(files["/p/.npmrc"]).toBe("registry=https://registry.npmjs.org/\n");
});

test("apply does not overwrite invalid existing yaml", () => {
  const invalid = "packages: [\n  - '.'\n";
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x","packageManager":"pnpm@10.0.0"}`,
    "/p/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
    "/p/pnpm-workspace.yaml": invalid,
  };
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
  const findings = auditSettings(project, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  const result = applySettings(project, findings, loadPolicy({}), {
    commit: false,
    force: false,
    gitStatus: () => "clean",
    readFile: (p) => files[p] ?? null,
    writeFile: (p, b) => {
      files[p] = b;
    },
  });
  expect(files["/p/pnpm-workspace.yaml"]).toBe(invalid);
  expect(result.written).not.toContain("/p/pnpm-workspace.yaml");
});

test("apply writes enableScripts: false to .yarnrc.yml preserving existing keys", () => {
  const files: Record<string, string> = {
    "/p/.yarnrc.yml": `npmRegistryServer: "https://registry.npmjs.org/"\n`,
    "/p/package.json": `{"name":"x","packageManager":"yarn@3.2.0"}`,
    "/p/yarn.lock": "",
  };
  const project: Project = {
    gitRoot: "/p",
    managers: [
      {
        configPath: "/p/.yarnrc.yml",
        lockfilePath: "/p/yarn.lock",
        manifestPath: "/p/package.json",
        name: "yarn",
        role: "primary",
      },
    ],
    root: "/p",
  };
  const findings = auditSettings(project, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.map((f) => f.code)).toEqual([
    "scripts.unrestricted",
    "min-age.disabled",
  ]);
  const result = applySettings(project, findings, loadPolicy({}), {
    commit: false,
    force: false,
    gitStatus: () => "clean",
    readFile: (p) => files[p] ?? null,
    writeFile: (p, b) => {
      files[p] = b;
    },
  });
  expect(result.skipped).toBeNull();
  expect(result.written).toContain("/p/.yarnrc.yml");
  expect(files["/p/.yarnrc.yml"]).toContain("enableScripts: false");
  // standard preset is 7 days, and yarn reads the gate in minutes.
  expect(files["/p/.yarnrc.yml"]).toContain("npmMinimalAgeGate: 10080");
  expect(files["/p/.yarnrc.yml"]).toContain("npmRegistryServer");
});

test("apply writes ignoreScripts to bunfig.toml preserving existing content", () => {
  const files: Record<string, string> = {
    "/p/bun.lock": "",
    "/p/bunfig.toml": `[install]\nregistry = "https://registry.npmjs.org/"\n`,
    "/p/package.json": `{"name":"x"}`,
  };
  const project: Project = {
    gitRoot: "/p",
    managers: [
      {
        configPath: "/p/bunfig.toml",
        lockfilePath: "/p/bun.lock",
        manifestPath: "/p/package.json",
        name: "bun",
        role: "primary",
      },
    ],
    root: "/p",
  };
  const findings = auditSettings(project, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.map((f) => f.code)).toEqual([
    "scripts.unrestricted",
    "min-age.disabled",
  ]);
  const result = applySettings(project, findings, loadPolicy({}), {
    commit: false,
    force: false,
    gitStatus: () => "clean",
    readFile: (p) => files[p] ?? null,
    writeFile: (p, b) => {
      files[p] = b;
    },
  });
  expect(result.skipped).toBeNull();
  expect(result.written).toContain("/p/bunfig.toml");
  expect(files["/p/bunfig.toml"]).toContain("ignoreScripts = true");
  // standard preset is 7 days, and bun reads the gate in seconds.
  expect(files["/p/bunfig.toml"]).toContain("minimumReleaseAge = 604800");
  expect(files["/p/bunfig.toml"]).toContain(
    'registry = "https://registry.npmjs.org/"'
  );
});

test("apply merges uv fix into existing [tool.uv] in pyproject.toml, not a new uv.toml", () => {
  const files: Record<string, string> = {
    "/p/pyproject.toml": `[project]\nname = "x"\n\n[tool.uv]\nindex-strategy = "unsafe-best-match"\n`,
    "/p/uv.lock": "",
  };
  const project: Project = {
    gitRoot: "/p",
    managers: [
      {
        // `configPath: null` (rather than pointing at pyproject.toml already)
        // forces `uvConfigPath` past its early manager.configPath return, so
        // this test actually exercises the `[tool.uv]`-detection branch that
        // reads pyproject.toml and checks for an existing `[tool.uv]` table.
        configPath: null,
        lockfilePath: "/p/uv.lock",
        manifestPath: "/p/pyproject.toml",
        name: "uv",
        role: "primary",
      },
    ],
    root: "/p",
  };
  const findings = auditSettings(project, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.map((f) => f.code)).toEqual(["min-age.disabled"]);
  const result = applySettings(project, findings, loadPolicy({}), {
    commit: false,
    force: false,
    gitStatus: () => "clean",
    readFile: (p) => files[p] ?? null,
    writeFile: (p, b) => {
      files[p] = b;
    },
  });
  expect(result.skipped).toBeNull();
  expect(result.written).toContain("/p/pyproject.toml");
  expect(files["/p/uv.toml"]).toBeUndefined();
  expect(files["/p/pyproject.toml"]).toContain(
    'index-strategy = "unsafe-best-match"'
  );
  expect(files["/p/pyproject.toml"]).toContain("exclude-newer");
});

test("apply writes uv fix into existing uv.toml", () => {
  const files: Record<string, string> = {
    "/p/pyproject.toml": `[project]\nname = "x"\n`,
    "/p/uv.lock": "",
    "/p/uv.toml": `index-strategy = "unsafe-best-match"\n`,
  };
  const project: Project = {
    gitRoot: "/p",
    managers: [
      {
        configPath: "/p/pyproject.toml",
        lockfilePath: "/p/uv.lock",
        manifestPath: "/p/pyproject.toml",
        name: "uv",
        role: "primary",
      },
    ],
    root: "/p",
  };
  const findings = auditSettings(project, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.map((f) => f.code)).toEqual(["min-age.disabled"]);
  const result = applySettings(project, findings, loadPolicy({}), {
    commit: false,
    force: false,
    gitStatus: () => "clean",
    readFile: (p) => files[p] ?? null,
    writeFile: (p, b) => {
      files[p] = b;
    },
  });
  expect(result.skipped).toBeNull();
  expect(result.written).toContain("/p/uv.toml");
  expect(files["/p/pyproject.toml"]).toBe(`[project]\nname = "x"\n`);
  expect(files["/p/uv.toml"]).toContain('index-strategy = "unsafe-best-match"');
  expect(files["/p/uv.toml"]).toContain("exclude-newer");
});

test("apply creates .npmrc when missing", () => {
  const files: Record<string, string> = {
    "/p/package-lock.json": `{}`,
    "/p/package.json": `{"name":"x"}`,
  };
  const project = npmProject("/p");
  const findings = auditSettings(project, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "scripts.unrestricted")).toBe(true);
  expect(files["/p/.npmrc"]).toBeUndefined();
  const result = applySettings(project, findings, loadPolicy({}), {
    commit: false,
    force: false,
    gitStatus: () => "clean",
    readFile: (p) => files[p] ?? null,
    writeFile: (p, b) => {
      files[p] = b;
    },
  });
  expect(result.skipped).toBeNull();
  expect(result.written).toContain("/p/.npmrc");
  expect(files["/p/.npmrc"]).toContain("ignore-scripts=true");
});

test("apply performs no writes when only non-fixable findings are present", () => {
  const leftover: Finding = {
    code: "lockfile.leftover",
    fixable: false,
    kind: "leftover-lockfile",
    manager: "npm",
    message: "Leftover npm lockfile is not an apply target",
    path: "/p/package-lock.json",
    severity: "high",
  };
  const unsupported: Finding = {
    code: "pm.unsupported",
    fixable: false,
    kind: "unsupported-pm",
    manager: "npm",
    message: "bower is unsupported",
    path: "/p/bower.json",
    severity: "high",
  };
  const notUsingUv: Finding = {
    code: "python.not-uv",
    fixable: false,
    kind: "not-using-uv",
    manager: "pip",
    message: "pip project is not using uv",
    path: "/p/requirements.txt",
    severity: "high",
  };
  // Give the project a real npm primary manager (rather than `managers: []`)
  // so that non-fixability of these findings is the only reason nothing is
  // written -- an empty `managers` array would produce no writes regardless.
  const project = npmProject("/p");
  const result = applySettings(
    project,
    [leftover, unsupported, notUsingUv],
    loadPolicy({}),
    {
      commit: false,
      force: false,
      gitStatus: () => "clean",
      readFile: () => null,
      writeFile: () => {
        throw new Error("must not write");
      },
    }
  );
  expect(result.written).toEqual([]);
  expect(result.skipped).toBe("nothing");
});

test("apply with --force writes on a dirty tree", () => {
  const files: Record<string, string> = {
    "/p/.npmrc": `registry=https://registry.npmjs.org/\n`,
    "/p/package-lock.json": `{}`,
    "/p/package.json": `{"name":"x"}`,
  };
  const project = npmProject("/p");
  const findings = auditSettings(project, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  const result = applySettings(project, findings, loadPolicy({}), {
    commit: false,
    force: true,
    gitStatus: () => "dirty",
    readFile: (p) => files[p] ?? null,
    writeFile: (p, b) => {
      files[p] = b;
    },
  });
  expect(result.skipped).toBeNull();
  expect(files["/p/.npmrc"]).toContain("ignore-scripts=true");
});

test("apply does not write lockfile.missing or pm.unpinned", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x"}`,
  };
  const project = npmProject("/p");
  const findings = auditSettings(project, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "lockfile.missing")).toBe(true);
  expect(findings.some((f) => f.code === "pm.unpinned")).toBe(true);
  const result = applySettings(project, findings, loadPolicy({}), {
    commit: false,
    force: false,
    gitStatus: () => "clean",
    readFile: (p) => files[p] ?? null,
    writeFile: (p, b) => {
      files[p] = b;
    },
  });
  expect(files["/p/package-lock.json"]).toBeUndefined();
  expect(files["/p/package.json"]).toBe(`{"name":"x"}`);
  expect(result.written).not.toContain("/p/package-lock.json");
  expect(result.written).not.toContain("/p/package.json");
});

test("apply creates missing pnpm-workspace.yaml, .yarnrc.yml, bunfig.toml, and uv.toml", () => {
  const cases: {
    files: Record<string, string>;
    project: Project;
    created: string;
    contains: string;
  }[] = [
    {
      contains: "minimumReleaseAge: 10080",
      created: "/p/pnpm-workspace.yaml",
      files: {
        "/p/package.json": `{"name":"x","packageManager":"pnpm@10.0.0"}`,
        "/p/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
      },
      project: {
        gitRoot: "/p",
        managers: [
          {
            configPath: "/p/pnpm-workspace.yaml",
            lockfilePath: "/p/pnpm-lock.yaml",
            manifestPath: "/p/package.json",
            name: "pnpm" as const,
            role: "primary" as const,
          },
        ],
        root: "/p",
      },
    },
    {
      contains: "enableScripts: false",
      created: "/p/.yarnrc.yml",
      files: {
        "/p/package.json": `{"name":"x","packageManager":"yarn@4.5.0"}`,
        "/p/yarn.lock": "# yarn\n",
      },
      project: {
        gitRoot: "/p",
        managers: [
          {
            configPath: "/p/.yarnrc.yml",
            lockfilePath: "/p/yarn.lock",
            manifestPath: "/p/package.json",
            name: "yarn" as const,
            role: "primary" as const,
          },
        ],
        root: "/p",
      },
    },
    {
      contains: "ignoreScripts = true",
      created: "/p/bunfig.toml",
      files: {
        "/p/bun.lock": "",
        "/p/package.json": `{"name":"x"}`,
      },
      project: {
        gitRoot: "/p",
        managers: [
          {
            configPath: "/p/bunfig.toml",
            lockfilePath: "/p/bun.lock",
            manifestPath: "/p/package.json",
            name: "bun" as const,
            role: "primary" as const,
          },
        ],
        root: "/p",
      },
    },
    {
      contains: "exclude-newer",
      created: "/p/uv.toml",
      files: {
        "/p/pyproject.toml": `[project]\nname = "x"\n`,
        "/p/uv.lock": "",
      },
      project: {
        gitRoot: "/p",
        managers: [
          {
            configPath: null,
            lockfilePath: "/p/uv.lock",
            manifestPath: "/p/pyproject.toml",
            name: "uv" as const,
            role: "primary" as const,
          },
        ],
        root: "/p",
      },
    },
  ];

  for (const row of cases) {
    const files: Record<string, string> = { ...row.files };
    expect(files[row.created]).toBeUndefined();
    const findings = auditSettings(row.project, loadPolicy({}), {
      readFile: (p) => files[p] ?? null,
    });
    const result = applySettings(row.project, findings, loadPolicy({}), {
      commit: false,
      force: false,
      gitStatus: () => "clean",
      readFile: (p) => files[p] ?? null,
      writeFile: (p, b) => {
        files[p] = b;
      },
    });
    expect(result.skipped).toBeNull();
    expect(result.written).toContain(row.created);
    expect(files[row.created]).toContain(row.contains);
  }
});

test("auditPath without --apply never writes", async () => {
  const files: Record<string, string> = {
    "/p/.npmrc": `registry=https://registry.npmjs.org/\n`,
    "/p/package-lock.json": `{}`,
    "/p/package.json": `{"name":"x"}`,
  };
  const result = await auditPath("/p", {
    apply: false,
    applyAdvisories: false,
    commit: false,
    concurrency: 4,
    deps: {
      gitStatus: () => "clean",
      isDir: (p) => p === "/p" || p === "/p/.git",
      readDir: (dir) => {
        if (dir === "/p") {
          return ["package.json", "package-lock.json", ".npmrc", ".git"];
        }
        return [];
      },
      readFile: (p) => files[p] ?? null,
      run: () => ({ code: 0, stderr: "", stdout: `{"advisories":{}}` }),
      which: () => "/usr/bin/npm",
      writeFile: () => {
        throw new Error("audit must not write");
      },
    },
    force: false,
    interactive: false,
    policy: loadPolicy({}),
  });
  expect(files["/p/.npmrc"]).toBe(`registry=https://registry.npmjs.org/\n`);
  expect(result.exitCode).toBe(1);
});

test("committed is false when git commit fails", () => {
  const files: Record<string, string> = {
    "/p/.npmrc": `registry=https://registry.npmjs.org/\n`,
    "/p/package-lock.json": `{}`,
    "/p/package.json": `{"name":"x"}`,
  };
  const project = npmProject("/p");
  const findings = auditSettings(project, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  const result = applySettings(project, findings, loadPolicy({}), {
    commit: true,
    force: false,
    gitCommit: () => false,
    gitStatus: () => "clean",
    readFile: (p) => files[p] ?? null,
    writeFile: (p, b) => {
      files[p] = b;
    },
  });
  expect(result.committed).toBe(false);
});
