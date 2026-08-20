import { expect, test } from "bun:test";
import { auditSettings } from "../src/settings";
import { loadPolicy } from "../src/policy";
import type { Project } from "../src/domain";

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

test("standard preset flags npm without ignore-scripts", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x"}`,
    "/p/package-lock.json": `{"lockfileVersion":3}`,
    "/p/.npmrc": `registry=https://registry.npmjs.org/\n`,
  };
  const findings = auditSettings(npmProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "scripts.unrestricted")).toBe(true);
});

test("standard preset is quiet on ignore-scripts when set", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x","packageManager":"npm@10.9.0"}`,
    "/p/package-lock.json": `{"lockfileVersion":3}`,
    "/p/.npmrc": `ignore-scripts=true\naudit=true\naudit-level=high\nmin-release-age=7\nregistry=https://registry.npmjs.org/\n`,
  };
  const findings = auditSettings(npmProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.filter((f) => f.kind === "settings")).toEqual([]);
});

test("leftover npm lockfile is a leftover finding and is not fixable", () => {
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
        configPath: null,
      },
    ],
  };
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x","packageManager":"pnpm@10.0.0"}`,
    "/p/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
    "/p/pnpm-workspace.yaml": "packages:\n  - '.'\nminimumReleaseAge: 10080\n",
  };
  const findings = auditSettings(project, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  const leftover = findings.find((f) => f.code === "lockfile.leftover");
  expect(leftover?.fixable).toBe(false);
  expect(leftover?.severity).toBe("high");
});
