import { expect, test } from "bun:test";

import { parseAuditOutput } from "../src/advisory-report";
import type { ParsedAuditReport } from "../src/advisory-report";
import type { Finding, FindingKind } from "../src/domain";

const findingOf = (
  report: ParsedAuditReport | null,
  kind: FindingKind = "advisory"
): Finding => {
  const finding = report?.findings.find((row) => row.kind === kind);
  if (finding === undefined) {
    throw new Error(`expected ${kind} finding`);
  }
  return finding;
};

test("parses npm classic advisories map", () => {
  const stdout = JSON.stringify({
    advisories: {
      "1": {
        findings: [{ version: "1.0.0" }],
        fixAvailable: { name: "left-pad", version: "1.3.0" },
        github_advisory_id: "GHSA-left-pad",
        module_name: "left-pad",
        severity: "high",
        title: "left-pad high advisory",
      },
    },
  });
  const finding = findingOf(
    parseAuditOutput("npm", stdout, "/p/package-lock.json")
  );
  expect(finding.package).toBe("left-pad");
  expect(finding.severity).toBe("high");
  expect(finding.kind).toBe("advisory");
  expect(finding.code).toBe("GHSA-left-pad");
});

test("parses npm v7 vulnerabilities map", () => {
  const stdout = JSON.stringify({
    auditReportVersion: 2,
    vulnerabilities: {
      "left-pad": {
        fixAvailable: { name: "left-pad", version: "1.3.0" },
        name: "left-pad",
        severity: "high",
        via: [
          {
            github_advisory_id: "GHSA-v7",
            severity: "high",
            title: "left-pad v7 advisory",
            version: "1.0.0",
          },
        ],
      },
    },
  });
  const finding = findingOf(
    parseAuditOutput("npm", stdout, "/p/package-lock.json")
  );
  expect(finding.package).toBe("left-pad");
  expect(finding.severity).toBe("high");
  expect(finding.kind).toBe("advisory");
  expect(finding.code).toBe("GHSA-v7");
});

test("parses pnpm classic advisories map", () => {
  const stdout = JSON.stringify({
    advisories: {
      "1092": {
        findings: [{ version: "3.0.0" }],
        fixAvailable: { name: "minimatch", version: "3.0.5" },
        github_advisory_id: "GHSA-pnpm-high",
        module_name: "minimatch",
        severity: "high",
        title: "minimatch high advisory",
      },
    },
    metadata: { vulnerabilities: { high: 1 } },
  });
  const finding = findingOf(
    parseAuditOutput("pnpm", stdout, "/pn/pnpm-lock.yaml")
  );
  expect(finding.package).toBe("minimatch");
  expect(finding.severity).toBe("high");
  expect(finding.kind).toBe("advisory");
  expect(finding.code).toBe("GHSA-pnpm-high");
});

test("parses yarn berry ndjson tree reporter output", () => {
  const lineOne = JSON.stringify({
    children: {
      Dependents: ["root-workspace-0b6124@workspace:."],
      ID: 1_094_464,
      Issue: "browserify-sign upper bound check issue in dsaVerify",
      Severity: "high",
      "Tree Versions": ["4.2.1"],
      URL: "https://github.com/advisories/GHSA-x9w5-v3q2-3rhw",
      "Vulnerable Versions": ">=2.6.0 <=4.2.1",
    },
    value: "browserify-sign",
  });
  const lineTwo = JSON.stringify({
    children: {
      Dependents: ["root-workspace-0b6124@workspace:."],
      ID: 1_098_445,
      Issue: "ansi-html Uncontrolled Resource Consumption",
      "Patched Versions": ">=0.0.8",
      Severity: "critical",
      "Tree Versions": ["0.0.7"],
      URL: "https://github.com/advisories/GHSA-whgm-jr23-g3j9",
      "Vulnerable Versions": "<0.0.8",
    },
    value: "ansi-html",
  });
  const report = parseAuditOutput(
    "yarn",
    `${lineOne}\n${lineTwo}\n`,
    "/yn/yarn.lock"
  );
  const advisories = report?.findings.filter((row) => row.kind === "advisory");
  expect(advisories).toHaveLength(2);
  const browserifySign = advisories?.find(
    (row) => row.package === "browserify-sign"
  );
  expect(browserifySign?.severity).toBe("high");
  expect(browserifySign?.kind).toBe("advisory");
  expect(browserifySign?.code).toBe("1094464");
  const ansiHtml = advisories?.find((row) => row.package === "ansi-html");
  expect(ansiHtml?.severity).toBe("critical");
  expect(ansiHtml?.kind).toBe("advisory");
  expect(ansiHtml?.code).toBe("1098445");
});

test("parses bun vulnerabilities map", () => {
  const stdout = JSON.stringify({
    auditReportVersion: 2,
    vulnerabilities: {
      "ansi-html": {
        fixAvailable: { name: "ansi-html", version: "0.0.8" },
        name: "ansi-html",
        range: "<0.0.8",
        severity: "critical",
        via: [
          {
            github_advisory_id: "GHSA-bun-crit",
            severity: "critical",
            title: "ansi-html critical advisory",
          },
        ],
      },
    },
  });
  const finding = findingOf(parseAuditOutput("bun", stdout, "/bn/bun.lock"));
  expect(finding.package).toBe("ansi-html");
  expect(finding.severity).toBe("critical");
  expect(finding.kind).toBe("advisory");
  expect(finding.code).toBe("GHSA-bun-crit");
});

test("parses uv deprecated and quarantine statuses", () => {
  const stdout = JSON.stringify([
    { name: "oldpkg", status: "deprecated", version: "1.0.0" },
    { name: "badpkg", status: "quarantine", version: "2.0.0" },
  ]);
  const report = parseAuditOutput("uv", stdout, "/uv/uv.lock");
  const deprecated = findingOf(report, "deprecated");
  expect(deprecated.package).toBe("oldpkg");
  expect(deprecated.kind).toBe("deprecated");
  const quarantine = findingOf(report, "quarantine");
  expect(quarantine.package).toBe("badpkg");
  expect(quarantine.kind).toBe("quarantine");
});

test("parses cargo vulnerabilities.list", () => {
  const stdout = JSON.stringify({
    vulnerabilities: {
      list: [
        {
          advisory: {
            id: "RUSTSEC-2024-0001",
            severity: "high",
            title: "serde high advisory",
          },
          package: { name: "serde", version: "1.0.0" },
        },
      ],
    },
  });
  const finding = findingOf(
    parseAuditOutput("cargo", stdout, "/rs/Cargo.lock")
  );
  expect(finding.package).toBe("serde");
  expect(finding.severity).toBe("high");
  expect(finding.kind).toBe("advisory");
  expect(finding.code).toBe("RUSTSEC-2024-0001");
});

test("parses bundle-audit results", () => {
  const stdout = JSON.stringify({
    created_at: "2026-01-01T00:00:00Z",
    results: [
      {
        advisory: {
          criticality: "high",
          ghsa: "whgm-jr23-g3j9",
          id: "CVE-2015-7576",
          patched_versions: [">= 4.2.5.1"],
          title: "Possible XSS vulnerability in rails",
        },
        gem: { name: "rails", version: "4.2.0" },
        type: "unpatched_gem",
      },
    ],
    version: "0.9.3",
  });
  const finding = findingOf(
    parseAuditOutput("bundler", stdout, "/rb/Gemfile.lock")
  );
  expect(finding.package).toBe("rails");
  expect(finding.severity).toBe("high");
  expect(finding.kind).toBe("advisory");
  expect(finding.code).toBe("CVE-2015-7576");
});

test("parses composer advisories object", () => {
  const stdout = JSON.stringify({
    abandoned: {},
    advisories: {
      "symfony/process": [
        {
          advisoryId: "PKSA-wws7-mr54-jsny",
          packageName: "symfony/process",
          severity: "high",
          title: "Command injection",
        },
      ],
    },
  });
  const finding = findingOf(
    parseAuditOutput("composer", stdout, "/php/composer.lock")
  );
  expect(finding.package).toBe("symfony/process");
  expect(finding.severity).toBe("high");
  expect(finding.kind).toBe("advisory");
  expect(finding.code).toBe("PKSA-wws7-mr54-jsny");
});

test("returns null for malformed JSON stdout", () => {
  expect(
    parseAuditOutput("npm", "{not-json", "/p/package-lock.json")
  ).toBeNull();
});
