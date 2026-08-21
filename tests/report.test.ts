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
        project: { gitRoot: "/p", managers: [], root: "/p" },
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
