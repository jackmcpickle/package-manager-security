import type { ApplyResult } from "./apply-settings";
import { isAdvisoryKind } from "./domain";
import type { Finding, PackageManager, Policy, Project } from "./domain";
import { profileFor } from "./managers/profile";
import { mapSerial } from "./std";
import { compareVersions } from "./version";

export type ApplyChoice = "settings" | "advisories" | "both" | "skip";

export type ApplyPrompt = (info: {
  project: Project;
  settingsCount: number;
  advisoryCount: number;
}) => ApplyChoice | Promise<ApplyChoice>;

interface Candidate {
  name: string;
  current: string;
  fixes: string[];
  manager: PackageManager;
}

const major = (version: string): string => {
  const match = version.match(/\d+/u);
  return match?.[0] ?? "";
};

const upgradeArgv = (
  manager: PackageManager,
  name: string,
  fix: string
): string[] | null => {
  const argv = profileFor(manager).upgradeArgv;
  return argv ? argv(name, fix) : null;
};

const findingManager = (
  finding: Finding,
  project: Project
): PackageManager | undefined => {
  const manager =
    finding.manager ??
    project.managers.find((row) => row.role === "primary")?.name;
  if (manager === undefined || profileFor(manager).kind === "python-legacy") {
    return;
  }
  return manager;
};

const upsertCandidate = (
  byName: Map<string, Candidate>,
  name: string,
  current: string,
  fix: string | undefined,
  manager: PackageManager
): void => {
  const existing = byName.get(name);
  if (existing === undefined) {
    byName.set(name, {
      current,
      fixes: fix === undefined ? [] : [fix],
      manager,
      name,
    });
    return;
  }
  if (fix !== undefined) {
    existing.fixes.push(fix);
  }
};

const addFindingCandidate = (
  byName: Map<string, Candidate>,
  finding: Finding,
  project: Project,
  deps: {
    currentVersions: Record<string, string>;
    fixVersions: Record<string, string>;
  }
): void => {
  if (!isAdvisoryKind(finding.kind) || finding.package === undefined) {
    return;
  }
  const manager = findingManager(finding, project);
  const current =
    finding.currentVersion ?? deps.currentVersions[finding.package];
  if (manager === undefined || current === undefined) {
    return;
  }
  upsertCandidate(
    byName,
    finding.package,
    current,
    finding.fixVersion ?? deps.fixVersions[finding.package],
    manager
  );
};

const collectCandidates = (
  project: Project,
  findings: Finding[],
  deps: {
    currentVersions: Record<string, string>;
    fixVersions: Record<string, string>;
  }
): Candidate[] => {
  const byName = new Map<string, Candidate>();
  for (const finding of findings) {
    addFindingCandidate(byName, finding, project, deps);
  }
  return [...byName.values()];
};

const sameMajorAllowed = (
  current: string,
  fix: string,
  allowMajor: boolean
): boolean => allowMajor || major(current) === major(fix);

const pickBestFix = (
  candidate: Candidate,
  allowMajor: boolean
): string | undefined => {
  const eligible = candidate.fixes.filter((fix) =>
    sameMajorAllowed(candidate.current, fix, allowMajor)
  );
  if (eligible.length === 0) {
    return;
  }
  let best = eligible[0] ?? "";
  for (const next of eligible) {
    if (compareVersions(next, best) > 0) {
      best = next;
    }
  }
  return best;
};

const upgradeCandidate = async (
  candidate: Candidate,
  allowMajor: boolean,
  run: (
    argv: string[],
    cwd: string
  ) => Promise<{ code: number; stdout: string; stderr: string }>,
  root: string
): Promise<string | null> => {
  const best = pickBestFix(candidate, allowMajor);
  if (best === undefined) {
    return null;
  }
  const argv = upgradeArgv(candidate.manager, candidate.name, best);
  if (argv === null) {
    return null;
  }
  const output = await run(argv, root);
  return output.code === 0 ? candidate.name : null;
};

export const applyAdvisories = async (
  project: Project,
  findings: Finding[],
  deps: {
    run: (
      argv: string[],
      cwd: string
    ) => Promise<{ code: number; stdout: string; stderr: string }>;
    allowMajors: boolean;
    currentVersions: Record<string, string>;
    fixVersions: Record<string, string>;
    policy?: Policy;
  }
): Promise<ApplyResult> => {
  const allowMajor = deps.allowMajors || deps.policy?.preset === "strict";
  const candidates = collectCandidates(project, findings, deps);
  const upgraded = await mapSerial(candidates, (candidate) =>
    upgradeCandidate(candidate, allowMajor, deps.run, project.root)
  );
  const written = upgraded.filter((name): name is string => name !== null);

  return {
    committed: false,
    skipped: written.length === 0 ? "nothing" : null,
    written,
  };
};
