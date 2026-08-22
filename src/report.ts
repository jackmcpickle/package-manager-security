import { agenticCaveat } from "./agentic";
import { APP_NAME } from "./app-name";
import type { ApplyChange, AuditResult } from "./audit";
import { gitRootOf, isAdvisoryKind } from "./domain";
import type { Finding, PackageManager, Project, Severity } from "./domain";

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
        const caveat = agenticCaveat(finding.code);
        lines.push(
          `- \`${finding.code}\` (${finding.severity}): ${finding.message}`
        );
        if (caveat !== null) {
          lines.push(`  ${caveat}`);
        }
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

const UNSET = "(unset)";

const applyStatusLabel = (status: ApplyChange["status"]): string =>
  status === "applied" ? "applied" : "skipped (dirty git tree)";

const padEnd = (text: string, width: number): string =>
  text.length >= width ? text : `${text}${" ".repeat(width - text.length)}`;

const colWidth = (cells: readonly string[]): number => {
  let width = 0;
  for (const cell of cells) {
    if (cell.length > width) {
      width = cell.length;
    }
  }
  return width;
};

const formatTable = (
  headers: readonly string[],
  rows: readonly (readonly string[])[],
  color: boolean,
  paintRow?: (cells: readonly string[], index: number) => readonly string[]
): string[] => {
  if (rows.length === 0) {
    return [];
  }
  const widths = headers.map((header, index) =>
    colWidth([header, ...rows.map((row) => row[index] ?? "")])
  );
  const line = (cells: readonly string[]): string =>
    `  ${cells.map((cell, index) => padEnd(cell, widths[index] ?? 0)).join("  ")}`;
  return [
    paint(line(headers), ANSI.bold, color),
    ...rows.map((row, index) =>
      line(paintRow ? (paintRow(row, index) ?? row) : row)
    ),
  ];
};

const managerLabel = (name: PackageManager, project: Project): string => {
  const manager = project.managers.find((row) => row.name === name);
  return manager === undefined ? name : `${name} (${manager.role})`;
};

const indexFindingsByManager = (
  findings: Finding[]
): { byManager: Map<PackageManager, Finding[]>; ungrouped: Finding[] } => {
  const byManager = new Map<PackageManager, Finding[]>();
  const ungrouped: Finding[] = [];
  for (const finding of findings) {
    if (finding.manager === undefined) {
      ungrouped.push(finding);
      continue;
    }
    const list = byManager.get(finding.manager) ?? [];
    list.push(finding);
    byManager.set(finding.manager, list);
  }
  return { byManager, ungrouped };
};

const managerGroups = (
  findings: Finding[],
  project: Project
): { label: string; findings: Finding[] }[] => {
  const { byManager, ungrouped } = indexFindingsByManager(findings);
  const groups: { label: string; findings: Finding[] }[] = [];
  const seen = new Set<PackageManager>();
  for (const manager of project.managers) {
    const list = byManager.get(manager.name);
    if (list === undefined || list.length === 0) {
      continue;
    }
    groups.push({
      findings: list,
      label: `${manager.name} (${manager.role})`,
    });
    seen.add(manager.name);
  }
  for (const [name, list] of byManager) {
    if (seen.has(name)) {
      continue;
    }
    groups.push({ findings: list, label: managerLabel(name, project) });
  }
  if (ungrouped.length > 0) {
    groups.push({ findings: ungrouped, label: "other" });
  }
  return groups;
};

const paintFindingCells = (
  cells: readonly string[],
  finding: Finding,
  color: boolean
): readonly string[] => [
  paint(cells[0] ?? "", ANSI.cyan, color),
  paint(cells[1] ?? "", SEVERITY_PAINT[finding.severity], color),
  cells[2] ?? "",
];

const caveatLines = (
  findings: Finding[],
  rows: readonly (readonly string[])[],
  color: boolean
): string[] => {
  const codeWidth = colWidth(rows.map((cells) => cells[0] ?? ""));
  const lines: string[] = [];
  for (const [index, finding] of findings.entries()) {
    const caveat = agenticCaveat(finding.code);
    const code = rows[index]?.[0];
    if (caveat === null || code === undefined) {
      continue;
    }
    lines.push(
      `  ${padEnd(code, codeWidth)}  ${paint(caveat, ANSI.dim, color)}`
    );
  }
  return lines;
};

const formatFindingsTable = (findings: Finding[], color: boolean): string[] => {
  if (findings.length === 0) {
    return [paint("  (none)", ANSI.dim, color)];
  }
  const headers = ["Code", "Severity", "Message"] as const;
  const rows = findings.map((finding) => [
    finding.code,
    finding.severity,
    finding.message,
  ]);
  const table = formatTable(headers, rows, color, (cells, index) => {
    const finding = findings[index];
    return finding === undefined
      ? cells
      : paintFindingCells(cells, finding, color);
  });
  return ["", ...table, ...caveatLines(findings, rows, color)];
};

const formatProjectFindings = (
  project: Project,
  findings: Finding[],
  color: boolean
): string[] => {
  const groups = managerGroups(findings, project);
  if (groups.length === 0) {
    return formatFindingsTable(findings, color);
  }
  const lines: string[] = [];
  for (const group of groups) {
    lines.push(
      "",
      paint(`  ${group.label}`, ANSI.bold, color),
      ...formatFindingsTable(group.findings, color)
    );
  }
  return lines;
};

const formatApplyTable = (changes: ApplyChange[], color: boolean): string[] => {
  if (changes.length === 0) {
    return [];
  }
  const headers = ["Setting", "Current", "Change to", "Status"] as const;
  const rows = changes.map((change) => [
    change.setting,
    change.current === "" ? UNSET : change.current,
    change.next,
    applyStatusLabel(change.status),
  ]);
  return ["", ...formatTable(headers, rows, color)];
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

const dirtyWarningLines = (
  gitRoot: string,
  skippedDirty: string[],
  warnedDirty: Set<string>,
  color: boolean
): string[] => {
  if (!skippedDirty.includes(gitRoot) || warnedDirty.has(gitRoot)) {
    return [];
  }
  warnedDirty.add(gitRoot);
  return [formatApplySkipped([gitRoot], { color }).trimEnd()];
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
  const warnedDirty = new Set<string>();
  for (const { project, findings: projectFindings } of result.projects) {
    lines.push(
      "",
      paint(project.root, ANSI.bold, color),
      ...formatProjectFindings(project, projectFindings, color)
    );
    const changes = (result.applyChanges ?? []).filter(
      (change) => change.projectRoot === project.root
    );
    lines.push(
      ...formatApplyTable(changes, color),
      ...dirtyWarningLines(
        gitRootOf(project),
        result.skippedDirty,
        warnedDirty,
        color
      )
    );
  }
  return `${lines.join("\n")}\n`;
};
