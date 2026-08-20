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
