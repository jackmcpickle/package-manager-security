import type { auditPath } from "./audit";

export function formatHuman(result: ReturnType<typeof auditPath>): string {
  const findings = result.projects.flatMap((row) => row.findings);
  const settingsCount = findings.filter((finding) => finding.kind !== "missing-binary").length;
  const warningsCount = findings.filter((finding) => finding.kind === "missing-binary").length;
  const lines = [
    `repos scanned: ${countRepos(result.projects)}`,
    `settings findings: ${settingsCount}`,
    `warnings: ${warningsCount}`,
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

function countRepos(projects: ReturnType<typeof auditPath>["projects"]): number {
  return new Set(projects.map(({ project }) => project.gitRoot ?? project.root)).size;
}
