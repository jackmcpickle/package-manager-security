import type { ApplyResult } from "./apply-settings";
import type { Finding, PackageManager, Policy, Project } from "./domain";

export type ApplyChoice = "settings" | "advisories" | "both" | "skip";

export type ApplyPrompt = (info: {
  project: Project;
  settingsCount: number;
  advisoryCount: number;
}) => ApplyChoice | Promise<ApplyChoice>;

const ADVISORY_KINDS = new Set(["advisory", "deprecated", "quarantine"]);
const NON_UV_PYTHON = new Set<PackageManager>(["poetry", "pip", "pipenv"]);

export function applyAdvisories(
  project: Project,
  findings: Finding[],
  deps: {
    run: (argv: string[], cwd: string) => Promise<{ code: number; stdout: string; stderr: string }>;
    allowMajors: boolean;
    currentVersions: Record<string, string>;
    fixVersions: Record<string, string>;
    policy?: Policy;
  },
): Promise<ApplyResult> {
  return applyAdvisoriesSerial(project, findings, deps);
}

async function applyAdvisoriesSerial(
  project: Project,
  findings: Finding[],
  deps: {
    run: (argv: string[], cwd: string) => Promise<{ code: number; stdout: string; stderr: string }>;
    allowMajors: boolean;
    currentVersions: Record<string, string>;
    fixVersions: Record<string, string>;
    policy?: Policy;
  },
): Promise<ApplyResult> {
  const allowMajor = deps.allowMajors || deps.policy?.preset === "strict";
  const written: string[] = [];

  for (const name of packageNames(findings, deps.fixVersions)) {
    const manager = managerFor(project, findings, name);
    if (manager === undefined || NON_UV_PYTHON.has(manager)) continue;
    const current = deps.currentVersions[name];
    const fix = deps.fixVersions[name];
    if (current === undefined || fix === undefined) continue;
    if (!allowMajor && major(current) !== major(fix)) continue;
    const argv = upgradeArgv(manager, name, fix);
    if (argv === null) continue;
    const output = await deps.run(argv, project.root);
    if (output.code === 0) written.push(name);
  }

  return { written, skipped: written.length === 0 ? "nothing" : null, committed: false };
}

function packageNames(findings: Finding[], fixVersions: Record<string, string>): string[] {
  const names: string[] = [];
  for (const name of Object.keys(fixVersions)) {
    if (findings.some((finding) => isAdvisory(finding) && mentions(finding, name))) {
      names.push(name);
    }
  }
  return names;
}

function isAdvisory(finding: Finding): boolean {
  return ADVISORY_KINDS.has(finding.kind);
}

function mentions(finding: Finding, name: string): boolean {
  return finding.message.includes(name) || finding.code.includes(name);
}

function managerFor(
  project: Project,
  findings: Finding[],
  name: string,
): PackageManager | undefined {
  const hit = findings.find((finding) => mentions(finding, name) && finding.manager !== undefined);
  if (hit?.manager !== undefined) return hit.manager;
  return project.managers.find((manager) => manager.role === "primary")?.name;
}

function upgradeArgv(manager: PackageManager, name: string, fix: string): string[] | null {
  switch (manager) {
    case "npm":
      return ["npm", "install", `${name}@${fix}`, "--save-exact"];
    case "pnpm":
      return ["pnpm", "add", `${name}@${fix}`];
    case "uv":
      return ["uv", "lock", "--upgrade-package", name];
    default:
      return null;
  }
}

function major(version: string): string {
  const match = version.match(/\d+/);
  return match?.[0] ?? "";
}
