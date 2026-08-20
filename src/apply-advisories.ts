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
  const candidates = collectCandidates(project, findings, deps);

  for (const candidate of candidates) {
    const eligible = candidate.fixes.filter(
      (fix) => allowMajor || major(candidate.current) === major(fix),
    );
    if (eligible.length === 0) continue;
    const fix = eligible.reduce((best, next) => (compareVersions(next, best) > 0 ? next : best));
    const argv = upgradeArgv(candidate.manager, candidate.name, fix);
    if (argv === null) continue;
    const output = await deps.run(argv, project.root);
    if (output.code === 0) written.push(candidate.name);
  }

  return { written, skipped: written.length === 0 ? "nothing" : null, committed: false };
}

type Candidate = {
  name: string;
  current: string;
  fixes: string[];
  manager: PackageManager;
};

function collectCandidates(
  project: Project,
  findings: Finding[],
  deps: {
    currentVersions: Record<string, string>;
    fixVersions: Record<string, string>;
  },
): Candidate[] {
  const byName = new Map<string, Candidate>();
  for (const finding of findings) {
    if (!ADVISORY_KINDS.has(finding.kind)) continue;
    const name = finding.package;
    if (name === undefined) continue;
    const manager = finding.manager ?? project.managers.find((row) => row.role === "primary")?.name;
    if (manager === undefined || NON_UV_PYTHON.has(manager)) continue;
    const current = finding.currentVersion ?? deps.currentVersions[name];
    const fix = finding.fixVersion ?? deps.fixVersions[name];
    if (current === undefined) continue;
    const existing = byName.get(name);
    if (existing === undefined) {
      byName.set(name, { name, current, fixes: fix === undefined ? [] : [fix], manager });
      continue;
    }
    if (fix !== undefined) existing.fixes.push(fix);
  }
  return [...byName.values()];
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

function compareVersions(left: string, right: string): number {
  const a = versionParts(left);
  const b = versionParts(right);
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const da = a[i] ?? 0;
    const db = b[i] ?? 0;
    if (da !== db) return da - db;
  }
  return 0;
}

function versionParts(version: string): number[] {
  return version.replace(/^v/i, "").split(/[.+-]/).map((part) => {
    const n = Number.parseInt(part, 10);
    return Number.isFinite(n) ? n : 0;
  });
}
