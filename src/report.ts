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

export function formatHuman(result: AuditResult): string {
  const findings = result.projects.flatMap((row) => row.findings);
  const settingsCount = findings.filter(
    (finding) => finding.kind !== "missing-binary" && !ADVISORY_KINDS.has(finding.kind),
  ).length;
  const warningsCount = findings.filter((finding) => finding.kind === "missing-binary").length;
  const advisoryCounts = countAdvisories(findings);
  const lines = [
    `repos scanned: ${countRepos(result.projects)}`,
    `settings findings: ${settingsCount}`,
    `warnings: ${warningsCount}`,
    `advisories: ${SEVERITIES.map((severity) => `${severity} ${advisoryCounts[severity]}`).join(", ")}`,
  ];
  for (const { project, findings: projectFindings } of result.projects) {
    lines.push("");
    lines.push(project.root);
    for (const finding of projectFindings) {
      lines.push(`  ${finding.code}  ${finding.severity}  ${finding.message}`);
    }
  }
  return `${lines.join("\n")}\n`;
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
