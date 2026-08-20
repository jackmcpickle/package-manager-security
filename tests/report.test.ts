import { expect, test } from "bun:test";

import type { AuditResult } from "../src/audit";
import type { Project } from "../src/domain";
import {
  formatHuman,
  formatJson,
  formatMarkdown,
  formatSarif,
} from "../src/report";

test("formatHuman includes repos scanned, settings findings count, and warnings count", () => {
  const project: Project = {
    gitRoot: "/p",
    managers: [],
    root: "/p",
  };
  const text = formatHuman({
    exitCode: 1,
    projects: [
      {
        findings: [
          {
            code: "scripts.unrestricted",
            fixable: true,
            kind: "settings",
            manager: "npm",
            message: "npm ignore-scripts must be true",
            path: "/p/.npmrc",
            severity: "high",
          },
          {
            code: "pm.missing-binary",
            fixable: false,
            kind: "missing-binary",
            manager: "npm",
            message: "Missing npm binary for npm",
            path: "/p/package.json",
            severity: "info",
          },
        ],
        project,
      },
    ],
    skippedDirty: [],
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
        findings: [],
        project: { gitRoot: "/repo", managers: [], root: "/repo/packages/a" },
      },
      {
        findings: [],
        project: { gitRoot: "/repo", managers: [], root: "/repo/packages/b" },
      },
    ],
    skippedDirty: [],
  });
  expect(text).toContain("repos scanned: 1");
});

test("formatHuman counts advisories by severity separately from settings", () => {
  const text = formatHuman({
    exitCode: 1,
    projects: [
      {
        findings: [
          {
            code: "scripts.unrestricted",
            fixable: true,
            kind: "settings",
            manager: "npm",
            message: "npm ignore-scripts must be true",
            path: "/p/.npmrc",
            severity: "high",
          },
          {
            code: "GHSA-x",
            fixable: false,
            kind: "advisory",
            manager: "npm",
            message: "critical pad",
            path: "/p/package-lock.json",
            severity: "critical",
          },
          {
            code: "GHSA-y",
            fixable: false,
            kind: "advisory",
            manager: "npm",
            message: "high pad",
            path: "/p/package-lock.json",
            severity: "high",
          },
        ],
        project: { gitRoot: "/p", managers: [], root: "/p" },
      },
    ],
    skippedDirty: [],
  });
  expect(text).toContain("settings findings: 1");
  expect(text).toMatch(/advisories:.*critical 1/u);
  expect(text).toMatch(/high 1/u);
});

const sampleResult: AuditResult = {
  exitCode: 1,
  projects: [
    {
      findings: [
        {
          code: "scripts.unrestricted",
          fixable: true,
          kind: "settings",
          manager: "npm",
          message: "npm ignore-scripts must be true",
          path: "/p/.npmrc",
          severity: "high",
        },
      ],
      project: { gitRoot: "/p", managers: [], root: "/p" },
    },
  ],
  skippedDirty: [],
};

test("format json and markdown include finding codes", () => {
  const json = formatJson(sampleResult);
  const md = formatMarkdown(sampleResult);
  expect(json).toContain("scripts.unrestricted");
  expect(md).toContain("scripts.unrestricted");
});

test("format sarif includes finding codes from the same result", () => {
  const sarif = formatSarif(sampleResult);
  expect(sarif).toContain("scripts.unrestricted");
  const parsed = JSON.parse(sarif) as { version: string };
  expect(parsed.version).toBe("2.1.0");
});

test("formatHuman with color wraps output in ANSI escapes; plain has none", () => {
  const colored = formatHuman(sampleResult, { color: true });
  expect(colored).toContain("\u001B[");
  expect(colored).toContain("scripts.unrestricted");
  const plain = formatHuman(sampleResult);
  expect(plain).not.toContain("\u001B[");
});
