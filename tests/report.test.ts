import { expect, test } from "bun:test";
import { formatHuman } from "../src/report";
import type { Project } from "../src/domain";

test("formatHuman includes repos scanned, settings findings count, and warnings count", () => {
  const project: Project = {
    root: "/p",
    gitRoot: "/p",
    managers: [],
  };
  const text = formatHuman({
    exitCode: 1,
    projects: [
      {
        project,
        findings: [
          {
            kind: "settings",
            code: "scripts.unrestricted",
            message: "npm ignore-scripts must be true",
            severity: "high",
            path: "/p/.npmrc",
            fixable: true,
            manager: "npm",
          },
          {
            kind: "missing-binary",
            code: "pm.missing-binary",
            message: "Missing npm binary for npm",
            severity: "info",
            path: "/p/package.json",
            fixable: false,
            manager: "npm",
          },
        ],
      },
    ],
  });
  expect(text).toContain("repos scanned");
  expect(text).toContain("settings findings");
  expect(text).toContain("warnings");
  expect(text).toContain("scripts.unrestricted");
});

test("formatHuman counts unique git roots as repos scanned", () => {
  const text = formatHuman({
    exitCode: 0,
    projects: [
      {
        project: { root: "/repo/packages/a", gitRoot: "/repo", managers: [] },
        findings: [],
      },
      {
        project: { root: "/repo/packages/b", gitRoot: "/repo", managers: [] },
        findings: [],
      },
    ],
  });
  expect(text).toContain("repos scanned: 1");
});
