import { expect, test } from "bun:test";

import type { Project } from "../src/domain";
import { preflight } from "../src/preflight";

test("missing pnpm is a warning finding and does not throw", () => {
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
  const result = preflight(project, { which: () => null });
  expect(result.missing).toEqual([{ binary: "pnpm", manager: "pnpm" }]);
  expect(result.warnings[0]?.code).toBe("pm.missing-binary");
});

test("leftover npm does not require the npm binary", () => {
  const project: Project = {
    gitRoot: "/p",
    managers: [
      {
        configPath: null,
        lockfilePath: "/p/pnpm-lock.yaml",
        manifestPath: "/p/package.json",
        name: "pnpm",
        role: "primary",
      },
      {
        configPath: null,
        lockfilePath: "/p/package-lock.json",
        manifestPath: "/p/package.json",
        name: "npm",
        role: "leftover",
      },
    ],
    root: "/p",
  };
  const result = preflight(project, {
    which: (b) => (b === "pnpm" ? "/usr/bin/pnpm" : null),
  });
  expect(result.missing).toEqual([]);
});

test("unsupported yarn requires no binary even when which returns null", () => {
  const project: Project = {
    gitRoot: "/y",
    managers: [
      {
        configPath: null,
        lockfilePath: "/y/yarn.lock",
        manifestPath: "/y/package.json",
        name: "yarn",
        role: "unsupported",
      },
    ],
    root: "/y",
  };
  const result = preflight(project, { which: () => null });
  expect(result.missing).toEqual([]);
  expect(result.warnings).toEqual([]);
});

test("poetry, pip, and pipenv primaries require no binary", () => {
  const project: Project = {
    gitRoot: "/py",
    managers: [
      {
        configPath: null,
        lockfilePath: "/py/poetry.lock",
        manifestPath: "/py/pyproject.toml",
        name: "poetry",
        role: "primary",
      },
      {
        configPath: null,
        lockfilePath: null,
        manifestPath: "/py/requirements.txt",
        name: "pip",
        role: "primary",
      },
      {
        configPath: null,
        lockfilePath: "/py/Pipfile.lock",
        manifestPath: "/py/Pipfile",
        name: "pipenv",
        role: "primary",
      },
    ],
    root: "/py",
  };
  const result = preflight(project, { which: () => null });
  expect(result.missing).toEqual([]);
});

test("missing yarn bun and uv primaries each emit pm.missing-binary", () => {
  for (const name of ["yarn", "bun", "uv"] as const) {
    const project: Project = {
      gitRoot: "/p",
      managers: [
        {
          configPath: null,
          lockfilePath: "/p/lock",
          manifestPath: "/p/manifest",
          name,
          role: "primary",
        },
      ],
      root: "/p",
    };
    const result = preflight(project, { which: () => null });
    expect(result.missing).toEqual([{ binary: name, manager: name }]);
    expect(result.warnings[0]).toEqual(
      expect.objectContaining({
        code: "pm.missing-binary",
        fixable: false,
        kind: "missing-binary",
        manager: name,
        severity: "info",
      })
    );
  }
});

test("uv primary does require the uv binary", () => {
  const project: Project = {
    gitRoot: "/py",
    managers: [
      {
        configPath: "/py/uv.toml",
        lockfilePath: "/py/uv.lock",
        manifestPath: "/py/pyproject.toml",
        name: "uv",
        role: "primary",
      },
    ],
    root: "/py",
  };
  const result = preflight(project, { which: () => null });
  expect(result.missing).toEqual([{ binary: "uv", manager: "uv" }]);
  expect(result.warnings[0]?.code).toBe("pm.missing-binary");
});
