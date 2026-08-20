import { expect, test } from "bun:test";
import { preflight } from "../src/preflight";
import type { Project } from "../src/domain";

test("missing pnpm is a warning finding and does not throw", () => {
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
  const result = preflight(project, { which: () => null });
  expect(result.missing).toEqual([{ manager: "pnpm", binary: "pnpm" }]);
  expect(result.warnings[0]?.code).toBe("pm.missing-binary");
});

test("leftover npm does not require the npm binary", () => {
  const project: Project = {
    root: "/p",
    gitRoot: "/p",
    managers: [
      {
        name: "pnpm",
        role: "primary",
        manifestPath: "/p/package.json",
        lockfilePath: "/p/pnpm-lock.yaml",
        configPath: null,
      },
      {
        name: "npm",
        role: "leftover",
        manifestPath: "/p/package.json",
        lockfilePath: "/p/package-lock.json",
        configPath: null,
      },
    ],
  };
  const result = preflight(project, { which: (b) => (b === "pnpm" ? "/usr/bin/pnpm" : null) });
  expect(result.missing).toEqual([]);
});

test("unsupported yarn requires no binary even when which returns null", () => {
  const project: Project = {
    root: "/y",
    gitRoot: "/y",
    managers: [
      {
        name: "yarn",
        role: "unsupported",
        manifestPath: "/y/package.json",
        lockfilePath: "/y/yarn.lock",
        configPath: null,
      },
    ],
  };
  const result = preflight(project, { which: () => null });
  expect(result.missing).toEqual([]);
  expect(result.warnings).toEqual([]);
});

test("poetry, pip, and pipenv primaries require no binary", () => {
  const project: Project = {
    root: "/py",
    gitRoot: "/py",
    managers: [
      {
        name: "poetry",
        role: "primary",
        manifestPath: "/py/pyproject.toml",
        lockfilePath: "/py/poetry.lock",
        configPath: null,
      },
      {
        name: "pip",
        role: "primary",
        manifestPath: "/py/requirements.txt",
        lockfilePath: null,
        configPath: null,
      },
      {
        name: "pipenv",
        role: "primary",
        manifestPath: "/py/Pipfile",
        lockfilePath: "/py/Pipfile.lock",
        configPath: null,
      },
    ],
  };
  const result = preflight(project, { which: () => null });
  expect(result.missing).toEqual([]);
});

test("missing yarn bun and uv primaries each emit pm.missing-binary", () => {
  for (const name of ["yarn", "bun", "uv"] as const) {
    const project: Project = {
      root: "/p",
      gitRoot: "/p",
      managers: [
        {
          name,
          role: "primary",
          manifestPath: "/p/manifest",
          lockfilePath: "/p/lock",
          configPath: null,
        },
      ],
    };
    const result = preflight(project, { which: () => null });
    expect(result.missing).toEqual([{ manager: name, binary: name }]);
    expect(result.warnings[0]).toEqual(
      expect.objectContaining({
        code: "pm.missing-binary",
        kind: "missing-binary",
        severity: "info",
        fixable: false,
        manager: name,
      }),
    );
  }
});

test("uv primary does require the uv binary", () => {
  const project: Project = {
    root: "/py",
    gitRoot: "/py",
    managers: [
      {
        name: "uv",
        role: "primary",
        manifestPath: "/py/pyproject.toml",
        lockfilePath: "/py/uv.lock",
        configPath: "/py/uv.toml",
      },
    ],
  };
  const result = preflight(project, { which: () => null });
  expect(result.missing).toEqual([{ manager: "uv", binary: "uv" }]);
  expect(result.warnings[0]?.code).toBe("pm.missing-binary");
});
