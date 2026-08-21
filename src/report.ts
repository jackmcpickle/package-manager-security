import { APP_NAME } from "./app-name";
import type { AuditResult } from "./audit";
import { gitRootOf, isAdvisoryKind } from "./domain";
import type { Finding, Severity } from "./domain";

const SEVERITIES: Severity[] = ["critical", "high", "moderate", "low", "info"];

const ANSI = {
  bold: "\u001B[1m",
  cyan: "\u001B[36m",
  dim: "\u001B[2m",
  red: "\u001B[31m",
  reset: "\u001B[0m",
  yellow: "\u001B[33m",
};

const SEVERITY_PAINT: Record<Severity, string> = {
  critical: ANSI.bold + ANSI.red,
  high: ANSI.red,
  info: ANSI.dim,
  low: ANSI.dim,
  moderate: ANSI.yellow,
};

const sarifLevel = (severity: Severity): "error" | "warning" | "note" => {
  if (severity === "critical" || severity === "high") {
    return "error";
  }
  if (severity === "moderate") {
    return "warning";
  }
  return "note";
};

const paint = (text: string, code: string, on: boolean): string =>
  on ? `${code}${text}${ANSI.reset}` : text;

const countAdvisories = (findings: Finding[]): Record<Severity, number> => {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    info: 0,
    low: 0,
    moderate: 0,
  };
  for (const finding of findings) {
    if (isAdvisoryKind(finding.kind)) {
      counts[finding.severity] += 1;
    }
  }
  return counts;
};

const countRepos = (projects: AuditResult["projects"]): number =>
  new Set(projects.map(({ project }) => gitRootOf(project))).size;

const withoutFix = (finding: Finding): Finding => {
  const { fix: _fix, ...rest } = finding;
  return rest;
};

export const formatJson = (result: AuditResult): string =>
  `${JSON.stringify({
    ...result,
    projects: result.projects.map((row) => ({
      ...row,
      findings: row.findings.map(withoutFix),
    })),
  })}\n`;

export const formatMarkdown = (result: AuditResult): string => {
  const lines = [`# ${APP_NAME} report`, ""];
  for (const { project, findings } of result.projects) {
    lines.push(`## ${project.root}`);
    if (findings.length === 0) {
      lines.push("- none");
    } else {
      for (const finding of findings) {
        lines.push(
          `- \`${finding.code}\` (${finding.severity}): ${finding.message}`
        );
      }
    }
    lines.push("");
  }
  return `${lines.join("\n")}\n`;
};

export const formatSarif = (result: AuditResult): string => {
  const findings = result.projects.flatMap((row) => row.findings);
  const rules = [
    ...new Map(findings.map((finding) => [finding.code, finding])).values(),
  ].map((finding) => ({
    id: finding.code,
    shortDescription: { text: finding.message },
  }));
  const results = findings.map((finding) => ({
    level: sarifLevel(finding.severity),
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: finding.path },
        },
      },
    ],
    message: { text: finding.message },
    ruleId: finding.code,
  }));
  return `${JSON.stringify({
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        results,
        tool: { driver: { name: APP_NAME, rules } },
      },
    ],
    version: "2.1.0",
  })}\n`;
};

export const formatHuman = (
  result: AuditResult,
  opts?: { color?: boolean }
): string => {
  const color = opts?.color ?? false;
  const findings = result.projects.flatMap((row) => row.findings);
  const settingsCount = findings.filter(
    (finding) =>
      finding.kind !== "missing-binary" && !isAdvisoryKind(finding.kind)
  ).length;
  const warningsCount = findings.filter(
    (finding) => finding.kind === "missing-binary"
  ).length;
  const advisoryCounts = countAdvisories(findings);
  const lines = [
    `repos scanned: ${paint(String(countRepos(result.projects)), ANSI.bold, color)}`,
    `settings findings: ${paint(String(settingsCount), ANSI.bold, color)}`,
    `warnings: ${paint(String(warningsCount), ANSI.bold, color)}`,
    `advisories: ${SEVERITIES.map(
      (severity) =>
        `${paint(severity, advisoryCounts[severity] > 0 ? SEVERITY_PAINT[severity] : ANSI.dim, color)} ${advisoryCounts[severity]}`
    ).join(", ")}`,
  ];
  for (const { project, findings: projectFindings } of result.projects) {
    lines.push("", paint(project.root, ANSI.bold, color));
    for (const finding of projectFindings) {
      lines.push(
        `  ${paint(finding.code, ANSI.cyan, color)}  ${paint(finding.severity, SEVERITY_PAINT[finding.severity], color)}  ${finding.message}`
      );
    }
  }
  return `${lines.join("\n")}\n`;
};

export const formatApplySkipped = (
  roots: string[],
  opts?: { color?: boolean }
): string => {
  const color = opts?.color ?? false;
  return roots
    .map((root) =>
      paint(
        `apply skipped: dirty git tree at ${root} (commit your changes or use --force)\n`,
        ANSI.yellow,
        color
      )
    )
    .join("");
};
