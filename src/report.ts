import type { AuditResult } from "./audit";
import type { Finding, Severity } from "./domain";

const ADVISORY_KINDS = new Set(["advisory", "deprecated", "quarantine"]);
const SEVERITIES: Severity[] = ["critical", "high", "moderate", "low", "info"];

export function formatJson(result: AuditResult): string {
  return `${JSON.stringify(result)}\n`;
}

export function formatMarkdown(result: AuditResult): string {
  const lines = ["# pmsec report", ""];
  for (const { project, findings } of result.projects) {
    lines.push(`## ${project.root}`);
    if (findings.length === 0) {
      lines.push("- none");
    } else {
      for (const finding of findings) {
        lines.push(`- \`${finding.code}\` (${finding.severity}): ${finding.message}`);
      }
    }
    lines.push("");
  }
  return `${lines.join("\n")}\n`;
}

export function formatSarif(result: AuditResult): string {
  const findings = result.projects.flatMap((row) => row.findings);
  const rules = [...new Map(findings.map((finding) => [finding.code, finding])).values()].map(
    (finding) => ({
      id: finding.code,
      shortDescription: { text: finding.message },
    }),
  );
  const results = findings.map((finding) => ({
    ruleId: finding.code,
    level: sarifLevel(finding.severity),
    message: { text: finding.message },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: finding.path },
        },
      },
    ],
  }));
  return `${JSON.stringify({
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "pmsec", rules } },
        results,
      },
    ],
  })}\n`;
}

function sarifLevel(severity: Severity): "error" | "warning" | "note" {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "moderate") return "warning";
  return "note";
}

const ANSI = {
  reset: "\u001b[0m",
  bold: "\u001b[1m",
  dim: "\u001b[2m",
  red: "\u001b[31m",
  yellow: "\u001b[33m",
  cyan: "\u001b[36m",
};

const SEVERITY_PAINT: Record<Severity, string> = {
  critical: ANSI.bold + ANSI.red,
  high: ANSI.red,
  moderate: ANSI.yellow,
  low: ANSI.dim,
  info: ANSI.dim,
};

function paint(text: string, code: string, on: boolean): string {
  return on ? `${code}${text}${ANSI.reset}` : text;
}

export function formatHuman(result: AuditResult, opts?: { color?: boolean }): string {
  const color = opts?.color ?? false;
  const findings = result.projects.flatMap((row) => row.findings);
  const settingsCount = findings.filter(
    (finding) => finding.kind !== "missing-binary" && !ADVISORY_KINDS.has(finding.kind),
  ).length;
  const warningsCount = findings.filter((finding) => finding.kind === "missing-binary").length;
  const advisoryCounts = countAdvisories(findings);
  const lines = [
    `repos scanned: ${paint(String(countRepos(result.projects)), ANSI.bold, color)}`,
    `settings findings: ${paint(String(settingsCount), ANSI.bold, color)}`,
    `warnings: ${paint(String(warningsCount), ANSI.bold, color)}`,
    `advisories: ${SEVERITIES.map(
      (severity) =>
        `${paint(severity, advisoryCounts[severity] > 0 ? SEVERITY_PAINT[severity] : ANSI.dim, color)} ${advisoryCounts[severity]}`,
    ).join(", ")}`,
  ];
  for (const { project, findings: projectFindings } of result.projects) {
    lines.push("");
    lines.push(paint(project.root, ANSI.bold, color));
    for (const finding of projectFindings) {
      lines.push(
        `  ${paint(finding.code, ANSI.cyan, color)}  ${paint(finding.severity, SEVERITY_PAINT[finding.severity], color)}  ${finding.message}`,
      );
    }
  }
  return `${lines.join("\n")}\n`;
}

export function formatApplySkipped(roots: string[], opts?: { color?: boolean }): string {
  const color = opts?.color ?? false;
  return roots
    .map((root) =>
      paint(
        `apply skipped: dirty git tree at ${root} (commit your changes or use --force)\n`,
        ANSI.yellow,
        color,
      ),
    )
    .join("");
}

function countAdvisories(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    moderate: 0,
    low: 0,
    info: 0,
  };
  for (const finding of findings) {
    if (ADVISORY_KINDS.has(finding.kind)) counts[finding.severity] += 1;
  }
  return counts;
}

function countRepos(projects: AuditResult["projects"]): number {
  return new Set(projects.map(({ project }) => project.gitRoot ?? project.root)).size;
}
