import { expect, test } from "bun:test";
import { formatHuman, formatJson, formatMarkdown, formatSarif } from "../src/report";
import type { Project } from "../src/domain";
import type { AuditResult } from "../src/audit";

test("formatHuman includes repos scanned, settings findings count, and warnings count", () => {
  const project: Project = {
    root: "/p",
    gitRoot: "/p",
    managers: [],
  };
  const text = formatHuman({
    exitCode: 1,
    skippedDirty: [],
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
    skippedDirty: [],
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

test("formatHuman counts advisories by severity separately from settings", () => {
  const text = formatHuman({
    exitCode: 1,
    skippedDirty: [],
    projects: [
      {
        project: { root: "/p", gitRoot: "/p", managers: [] },
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
            kind: "advisory",
            code: "GHSA-x",
            message: "critical pad",
            severity: "critical",
            path: "/p/package-lock.json",
            fixable: false,
            manager: "npm",
          },
          {
            kind: "advisory",
            code: "GHSA-y",
            message: "high pad",
            severity: "high",
            path: "/p/package-lock.json",
            fixable: false,
            manager: "npm",
          },
        ],
      },
    ],
  });
  expect(text).toContain("settings findings: 1");
  expect(text).toMatch(/advisories:.*critical 1/);
  expect(text).toMatch(/high 1/);
});

const sampleResult: AuditResult = {
  exitCode: 1,
  skippedDirty: [],
  projects: [
    {
      project: { root: "/p", gitRoot: "/p", managers: [] },
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
      ],
    },
  ],
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
  expect(colored).toContain("\u001b[");
  expect(colored).toContain("scripts.unrestricted");
  const plain = formatHuman(sampleResult);
  expect(plain).not.toContain("\u001b[");
});
