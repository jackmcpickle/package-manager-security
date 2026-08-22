import { expect, test } from "bun:test";

import type { AuditResult } from "../src/audit";
import type { Project } from "../src/domain";
import {
  formatHuman,
  formatJson,
  formatMarkdown,
  formatSarif,
} from "../src/report";

const npmProject = (root = "/p"): Project => ({
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

test("formatHuman includes repos scanned, settings findings count, and warnings count", () => {
  const project = npmProject();
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
  expect(text).toContain("Code");
  expect(text).toContain("Severity");
  expect(text).toContain("Message");
  expect(text).toContain("npm (primary)");
});

test("formatHuman prints the catalog caveat under an agentic finding", () => {
  const text = formatHuman({
    exitCode: 0,
    projects: [
      {
        findings: [
          {
            code: "overrides.present",
            fixable: false,
            kind: "settings",
            manager: "npm",
            message:
              "overrides create a version precedent the next agent will copy",
            path: "/p/package.json",
            severity: "info",
          },
        ],
        project: npmProject(),
      },
    ],
    skippedDirty: [],
  });
  expect(text).toContain("overrides.present");
  expect(text).toContain("apply never deletes a pin");
});

test("formatMarkdown prints the catalog caveat under an agentic finding", () => {
  const text = formatMarkdown({
    exitCode: 0,
    projects: [
      {
        findings: [
          {
            code: "cache.path-committed",
            fixable: false,
            kind: "settings",
            manager: "npm",
            message:
              "committed store or cache path should not live in project config",
            path: "/p/.npmrc",
            severity: "info",
          },
        ],
        project: npmProject(),
      },
    ],
    skippedDirty: [],
  });
  expect(text).toContain("cache.path-committed");
  expect(text).toContain("never writes");
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
        project: npmProject(),
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
      project: npmProject(),
    },
  ],
  skippedDirty: [],
};

test("formatHuman groups findings by package manager within a project", () => {
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
            code: "lockfile.leftover",
            fixable: false,
            kind: "leftover-lockfile",
            manager: "yarn",
            message: "Leftover yarn lockfile is not an apply target",
            path: "/p/yarn.lock",
            severity: "high",
          },
        ],
        project: {
          gitRoot: "/p",
          managers: [
            {
              configPath: "/p/.npmrc",
              lockfilePath: "/p/package-lock.json",
              manifestPath: "/p/package.json",
              name: "npm",
              role: "primary",
            },
            {
              configPath: null,
              lockfilePath: "/p/yarn.lock",
              manifestPath: "/p/package.json",
              name: "yarn",
              role: "leftover",
            },
          ],
          root: "/p",
        },
      },
    ],
    skippedDirty: [],
  });
  const npmAt = text.indexOf("npm (primary)");
  const yarnAt = text.indexOf("yarn (leftover)");
  const npmFindingAt = text.indexOf("scripts.unrestricted");
  const yarnFindingAt = text.indexOf("lockfile.leftover");
  expect(npmAt).toBeGreaterThan(-1);
  expect(yarnAt).toBeGreaterThan(npmAt);
  expect(npmFindingAt).toBeGreaterThan(npmAt);
  expect(yarnFindingAt).toBeGreaterThan(yarnAt);
  expect(npmFindingAt).toBeLessThan(yarnAt);
});

test("format json and markdown include finding codes", () => {
  const json = formatJson(sampleResult);
  const md = formatMarkdown(sampleResult);
  expect(json).toContain("scripts.unrestricted");
  expect(md).toContain("scripts.unrestricted");
});

test("formatJson omits finding.fix from the serialized report", () => {
  const result: AuditResult = {
    exitCode: 1,
    projects: [
      {
        findings: [
          {
            code: "scripts.unrestricted",
            fix: {
              edits: [{ key: "ignore-scripts", op: "set", value: true }],
              file: "/p/.npmrc",
              format: "npmrc",
            },
            fixable: true,
            kind: "settings",
            manager: "npm",
            message: "npm ignore-scripts must be true",
            path: "/p/.npmrc",
            severity: "high",
          },
        ],
        project: npmProject(),
      },
    ],
    skippedDirty: [],
  };
  const parsed = JSON.parse(formatJson(result)) as {
    projects: { findings: Record<string, unknown>[] }[];
  };
  const [finding] = parsed.projects[0]?.findings ?? [];
  expect(finding).toBeDefined();
  expect(finding).not.toHaveProperty("fix");
  expect(finding?.code).toBe("scripts.unrestricted");
  expect(finding?.fixable).toBe(true);
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

test("formatHuman shows apply table and dirty skip after the folder", () => {
  const text = formatHuman({
    applyChanges: [
      {
        current: "(unset)",
        next: "true",
        projectRoot: "/p",
        setting: "ignore-scripts",
        status: "skipped-dirty",
      },
    ],
    exitCode: 2,
    projects: sampleResult.projects,
    skippedDirty: ["/p"],
  });
  const folderAt = text.indexOf("\n/p\n");
  const tableAt = text.indexOf("Change to");
  const rowAt = text.search(
    /ignore-scripts\s+\(unset\)\s+true\s+skipped \(dirty git tree\)/u
  );
  const warnAt = text.indexOf("apply skipped: dirty git tree at /p");
  expect(text).toContain("Setting");
  expect(text).toContain("Current");
  expect(text).toContain("Status");
  expect(folderAt).toBeGreaterThan(-1);
  expect(tableAt).toBeGreaterThan(folderAt);
  expect(rowAt).toBeGreaterThan(tableAt);
  expect(warnAt).toBeGreaterThan(rowAt);
});

test("formatHuman emits one dirty warning for projects that share a git root", () => {
  const finding = {
    code: "scripts.unrestricted",
    fixable: true,
    kind: "settings" as const,
    manager: "npm" as const,
    message: "npm ignore-scripts must be true",
    path: "/repo/.npmrc",
    severity: "high" as const,
  };
  const text = formatHuman({
    applyChanges: [
      {
        current: "(unset)",
        next: "true",
        projectRoot: "/repo/a",
        setting: "ignore-scripts",
        status: "skipped-dirty",
      },
      {
        current: "(unset)",
        next: "1440",
        projectRoot: "/repo/b",
        setting: "minimumReleaseAge",
        status: "skipped-dirty",
      },
    ],
    exitCode: 2,
    projects: [
      {
        findings: [finding],
        project: { gitRoot: "/repo", managers: [], root: "/repo/a" },
      },
      {
        findings: [finding],
        project: { gitRoot: "/repo", managers: [], root: "/repo/b" },
      },
    ],
    skippedDirty: ["/repo"],
  });
  expect(text).toContain("/repo/a");
  expect(text).toContain("/repo/b");
  expect(text).toContain("Change to");
  expect(text.match(/apply skipped: dirty git tree at \/repo/gu)).toHaveLength(
    1
  );
});

test("formatHuman marks applied changes in the table and omits the dirty warning", () => {
  const text = formatHuman({
    applyChanges: [
      {
        current: "(unset)",
        next: "true",
        projectRoot: "/p",
        setting: "ignore-scripts",
        status: "applied",
      },
    ],
    exitCode: 1,
    projects: sampleResult.projects,
    skippedDirty: [],
  });
  expect(text).toContain("ignore-scripts");
  expect(text).toContain("(unset)");
  expect(text).toContain("applied");
  expect(text).not.toContain("apply skipped");
  expect(text).not.toContain("skipped (dirty git tree)");
});
