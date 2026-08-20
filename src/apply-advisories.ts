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
  const a = parseSemver(left);
  const b = parseSemver(right);
  for (let i = 0; i < 3; i++) {
    if (a.core[i] !== b.core[i]) return a.core[i]! - b.core[i]!;
  }
  if (a.pre.length === 0 && b.pre.length === 0) return 0;
  if (a.pre.length === 0) return 1;
  if (b.pre.length === 0) return -1;
  const len = Math.max(a.pre.length, b.pre.length);
  for (let i = 0; i < len; i++) {
    if (i >= a.pre.length) return -1;
    if (i >= b.pre.length) return 1;
    const da = a.pre[i]!;
    const db = b.pre[i]!;
    if (da === db) continue;
    const na = typeof da === "number";
    const nb = typeof db === "number";
    if (na && nb) return da - db;
    if (na) return -1;
    if (nb) return 1;
    return da < db ? -1 : 1;
  }
  return 0;
}

function parseSemver(version: string): { core: number[]; pre: Array<string | number> } {
  const trimmed = version.trim().replace(/^v/i, "");
  const plus = trimmed.indexOf("+");
  const noBuild = plus === -1 ? trimmed : trimmed.slice(0, plus);
  const dash = noBuild.indexOf("-");
  const coreStr = dash === -1 ? noBuild : noBuild.slice(0, dash);
  const preStr = dash === -1 ? "" : noBuild.slice(dash + 1);
  const core = coreStr.split(".").map((part) => {
    const n = Number.parseInt(part, 10);
    return Number.isFinite(n) ? n : 0;
  });
  while (core.length < 3) core.push(0);
  const pre =
    preStr === ""
      ? []
      : preStr.split(".").map((id) => (/^\d+$/.test(id) ? Number(id) : id));
  return { core: core.slice(0, 3), pre };
}
