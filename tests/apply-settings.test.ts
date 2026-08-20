import { expect, test } from "bun:test";
import { applySettings } from "../src/apply-settings";
import { auditPath } from "../src/audit";
import type { Finding, Project } from "../src/domain";
import { loadPolicy } from "../src/policy";
import { auditSettings } from "../src/settings";

function npmProject(root: string): Project {
  return {
    root,
    gitRoot: root,
    managers: [
      {
        name: "npm",
        role: "primary",
        manifestPath: `${root}/package.json`,
        lockfilePath: `${root}/package-lock.json`,
        configPath: `${root}/.npmrc`,
      },
    ],
  };
}

test("apply writes ignore-scripts to .npmrc on a clean tree", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x"}`,
    "/p/package-lock.json": `{}`,
    "/p/.npmrc": `registry=https://registry.npmjs.org/\n`,
  };
  const project = npmProject("/p");
  const findings = auditSettings(project, loadPolicy({}), { readFile: (p) => files[p] ?? null });
  const result = applySettings(project, findings, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
    writeFile: (p, b) => {
      files[p] = b;
    },
    gitStatus: () => "clean",
    force: false,
    commit: false,
  });
  expect(result.skipped).toBeNull();
  expect(files["/p/.npmrc"]).toContain("ignore-scripts=true");
});

test("apply skips a dirty tree without force", () => {
  const project = npmProject("/p");
  const findings = auditSettings(project, loadPolicy({}), { readFile: () => null });
  const result = applySettings(project, findings, loadPolicy({}), {
    readFile: () => null,
    writeFile: () => {
      throw new Error("must not write");
    },
    gitStatus: () => "dirty",
    force: false,
    commit: false,
  });
  expect(result.skipped).toBe("dirty");
});

test("apply writes pnpm keys to pnpm-workspace.yaml not .npmrc", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x","packageManager":"pnpm@10.0.0"}`,
    "/p/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
    "/p/pnpm-workspace.yaml": "packages:\n  - '.'\n",
    "/p/.npmrc": "registry=https://registry.npmjs.org/\n",
  };
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
  const findings = auditSettings(project, loadPolicy({}), { readFile: (p) => files[p] ?? null });
  const result = applySettings(project, findings, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
    writeFile: (p, b) => {
      files[p] = b;
    },
    gitStatus: () => "clean",
    force: false,
    commit: false,
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
  const findings = auditSettings(project, loadPolicy({}), { readFile: (p) => files[p] ?? null });
  const result = applySettings(project, findings, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
    writeFile: (p, b) => {
      files[p] = b;
    },
    gitStatus: () => "clean",
    force: false,
    commit: false,
  });
  expect(result.skipped).toBeNull();
  expect(files["/p/pnpm-workspace.yaml"]).toContain("minimumReleaseAge: 10080");
});

test("apply does not write leftover lockfiles or ~/.npmrc", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x","packageManager":"pnpm@10.0.0"}`,
    "/p/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
    "/p/package-lock.json": "{}",
    "/home/user/.npmrc": "ignore-scripts=false\n",
  };
  const leftover: Finding = {
    kind: "leftover-lockfile",
    code: "lockfile.leftover",
    message: "Leftover npm lockfile is not an apply target",
    severity: "high",
    path: "/p/package-lock.json",
    fixable: false,
    manager: "npm",
  };
  const home: Finding = {
    kind: "settings",
    code: "scripts.unrestricted",
    message: "npm ignore-scripts must be true",
    severity: "high",
    path: "~/.npmrc",
    fixable: true,
    manager: "npm",
  };
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
      {
        name: "npm",
        role: "leftover",
        manifestPath: "/p/package.json",
        lockfilePath: "/p/package-lock.json",
        configPath: "~/.npmrc",
      },
    ],
  };
  const result = applySettings(project, [leftover, home], loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
    writeFile: (p, b) => {
      files[p] = b;
    },
    gitStatus: () => "clean",
    force: false,
    commit: false,
  });
  expect(files["/p/package-lock.json"]).toBe("{}");
  expect(files["~/.npmrc"]).toBeUndefined();
  expect(files["/home/user/.npmrc"]).toBe("ignore-scripts=false\n");
  expect(result.written).not.toContain("/p/package-lock.json");
  expect(result.written).not.toContain("~/.npmrc");
});

test("auditPath maps apply skipped dirty to exit 2", async () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x"}`,
    "/p/package-lock.json": `{}`,
    "/p/.npmrc": `registry=https://registry.npmjs.org/\n`,
  };
  const result = await auditPath("/p", {
    policy: loadPolicy({}),
    apply: true,
    applyAdvisories: false,
    interactive: false,
    concurrency: 4,
    force: false,
    commit: false,
    deps: {
      readFile: (p) => files[p] ?? null,
      readDir: (dir) => {
        if (dir === "/p") return ["package.json", "package-lock.json", ".npmrc", ".git"];
        return [];
      },
      isDir: (p) => p === "/p" || p === "/p/.git",
      which: () => "/usr/bin/npm",
      run: async () => ({ code: 0, stdout: `{"advisories":{}}`, stderr: "" }),
      writeFile: () => {
        throw new Error("must not write");
      },
      gitStatus: () => "dirty",
    },
  });
  expect(result.exitCode).toBe(2);
});

test("auditPath apply on a clean tree writes settings and is not the stub exit 2", async () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x"}`,
    "/p/package-lock.json": `{}`,
    "/p/.npmrc": `registry=https://registry.npmjs.org/\n`,
  };
  const result = await auditPath("/p", {
    policy: loadPolicy({}),
    apply: true,
    applyAdvisories: false,
    interactive: false,
    concurrency: 4,
    force: false,
    commit: false,
    deps: {
      readFile: (p) => files[p] ?? null,
      readDir: (dir) => {
        if (dir === "/p") return ["package.json", "package-lock.json", ".npmrc", ".git"];
        return [];
      },
      isDir: (p) => p === "/p" || p === "/p/.git",
      which: () => "/usr/bin/npm",
      run: async () => ({ code: 0, stdout: `{"advisories":{}}`, stderr: "" }),
      writeFile: (p, b) => {
        files[p] = b;
      },
      gitStatus: () => "clean",
    },
  });
  expect(files["/p/.npmrc"]).toContain("ignore-scripts=true");
  expect(result.exitCode).not.toBe(2);
});

test("two npm/pnpm roots sharing a gitRoot both get written without force", async () => {
  const files: Record<string, string> = {
    "/repo/a/package.json": `{"name":"a"}`,
    "/repo/a/package-lock.json": `{}`,
    "/repo/a/.npmrc": `registry=https://registry.npmjs.org/\n`,
    "/repo/b/package.json": `{"name":"b","packageManager":"pnpm@10.0.0"}`,
    "/repo/b/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
    "/repo/b/pnpm-workspace.yaml": "packages:\n  - '.'\n",
  };
  let tree: "clean" | "dirty" = "clean";
  const commits: Array<{ root: string; files: string[] }> = [];
  const result = await auditPath("/repo", {
    policy: loadPolicy({}),
    apply: true,
    applyAdvisories: false,
    interactive: false,
    concurrency: 4,
    force: false,
    commit: true,
    deps: {
      readFile: (p) => files[p] ?? null,
      readDir: (dir) => {
        if (dir === "/repo") return [".git", "a", "b"];
        if (dir === "/repo/a") return ["package.json", "package-lock.json", ".npmrc"];
        if (dir === "/repo/b") return ["package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml"];
        return [];
      },
      isDir: (p) =>
        p === "/repo" || p === "/repo/.git" || p === "/repo/a" || p === "/repo/b",
      which: () => "/usr/bin/npm",
      run: async () => ({ code: 0, stdout: `{"advisories":{}}`, stderr: "" }),
      writeFile: (p, b) => {
        files[p] = b;
        tree = "dirty";
      },
      gitStatus: () => tree,
      gitCommit: (root, _message, written) => {
        commits.push({ root, files: written });
        return true;
      },
    },
  });
  expect(files["/repo/a/.npmrc"]).toContain("ignore-scripts=true");
  expect(files["/repo/b/pnpm-workspace.yaml"]).toContain("onlyBuiltDependencies");
  expect(commits).toEqual([
    {
      root: "/repo",
      files: ["/repo/a/.npmrc", "/repo/b/pnpm-workspace.yaml"],
    },
  ]);
  expect(result.exitCode).not.toBe(2);
});

test("apply skips a not-git tree without force", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x"}`,
    "/p/package-lock.json": `{}`,
    "/p/.npmrc": `registry=https://registry.npmjs.org/\n`,
  };
  const project = npmProject("/p");
  const findings = auditSettings(project, loadPolicy({}), { readFile: (p) => files[p] ?? null });
  const result = applySettings(project, findings, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
    writeFile: () => {
      throw new Error("must not write");
    },
    gitStatus: () => "not-git",
    force: false,
    commit: false,
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
  const findings = auditSettings(project, loadPolicy({}), { readFile: (p) => files[p] ?? null });
  const result = applySettings(project, findings, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
    writeFile: (p, b) => {
      files[p] = b;
    },
    gitStatus: () => "clean",
    force: false,
    commit: false,
  });
  expect(files["/p/pnpm-workspace.yaml"]).toBe(invalid);
  expect(result.written).not.toContain("/p/pnpm-workspace.yaml");
});

test("committed is false when git commit fails", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x"}`,
    "/p/package-lock.json": `{}`,
    "/p/.npmrc": `registry=https://registry.npmjs.org/\n`,
  };
  const project = npmProject("/p");
  const findings = auditSettings(project, loadPolicy({}), { readFile: (p) => files[p] ?? null });
  const result = applySettings(project, findings, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
    writeFile: (p, b) => {
      files[p] = b;
    },
    gitStatus: () => "clean",
    force: false,
    commit: true,
    gitCommit: () => false,
  });
  expect(result.committed).toBe(false);
});
