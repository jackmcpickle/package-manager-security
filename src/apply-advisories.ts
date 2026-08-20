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

export async function applyAdvisories(
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
  const seen = new Set<string>();

  for (const finding of findings) {
    if (!ADVISORY_KINDS.has(finding.kind)) continue;
    const name = finding.package;
    if (name === undefined || seen.has(name)) continue;
    const manager = finding.manager ?? project.managers.find((row) => row.role === "primary")?.name;
    if (manager === undefined || NON_UV_PYTHON.has(manager)) continue;
    const current = finding.currentVersion ?? deps.currentVersions[name];
    const fix = finding.fixVersion ?? deps.fixVersions[name];
    if (current === undefined || fix === undefined) continue;
    if (!allowMajor && major(current) !== major(fix)) continue;
    const argv = upgradeArgv(manager, name, fix);
    if (argv === null) continue;
    seen.add(name);
    const output = await deps.run(argv, project.root);
    if (output.code === 0) written.push(name);
  }

  return { written, skipped: written.length === 0 ? "nothing" : null, committed: false };
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
