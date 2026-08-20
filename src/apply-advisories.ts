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

interface Candidate {
  name: string;
  current: string;
  fixes: string[];
  manager: PackageManager;
}

const parseSemverCore = (coreStr: string): number[] => {
  const core = coreStr.split(".").map((part) => {
    const n = Math.trunc(Number(part));
    return Number.isFinite(n) ? n : 0;
  });
  while (core.length < 3) {
    core.push(0);
  }
  return core.slice(0, 3);
};

const parseSemverPre = (preStr: string): (string | number)[] => {
  if (preStr === "") {
    return [];
  }
  return preStr.split(".").map((id) => (/^\d+$/u.test(id) ? Number(id) : id));
};

const parseSemver = (
  version: string
): {
  core: number[];
  pre: (string | number)[];
} => {
  const trimmed = version.trim().replace(/^v/iu, "");
  const plus = trimmed.indexOf("+");
  const noBuild = plus === -1 ? trimmed : trimmed.slice(0, plus);
  const dash = noBuild.indexOf("-");
  const coreStr = dash === -1 ? noBuild : noBuild.slice(0, dash);
  const preStr = dash === -1 ? "" : noBuild.slice(dash + 1);
  return { core: parseSemverCore(coreStr), pre: parseSemverPre(preStr) };
};

const compareCore = (left: number[], right: number[]): number => {
  for (let i = 0; i < 3; i += 1) {
    const av = left[i] ?? 0;
    const bv = right[i] ?? 0;
    if (av !== bv) {
      return av - bv;
    }
  }
  return 0;
};

const bothNumeric = (left: string | number, right: string | number): boolean =>
  typeof left === "number" && typeof right === "number";

const hasNumericPre = (
  left: string | number,
  right: string | number
): boolean => typeof left === "number" || typeof right === "number";

const firstNumericWins = (left: string | number): number =>
  typeof left === "number" ? -1 : 1;

const stringPreCmp = (left: string, right: string): number =>
  Number(left > right) - Number(left < right);

const comparePreIdMixed = (
  left: string | number,
  right: string | number
): number => {
  if (hasNumericPre(left, right)) {
    return firstNumericWins(left);
  }
  return stringPreCmp(String(left), String(right));
};

const comparePreId = (
  left: string | number,
  right: string | number
): number => {
  if (bothNumeric(left, right)) {
    return (left as number) - (right as number);
  }
  return comparePreIdMixed(left, right);
};

const prePresence = (leftLen: number, rightLen: number): number | null => {
  if (leftLen === 0 && rightLen === 0) {
    return 0;
  }
  if (leftLen === 0) {
    return 1;
  }
  if (rightLen === 0) {
    return -1;
  }
  return null;
};

const pastEnd = (
  index: number,
  len: number,
  past: number,
  within: number | null
): number | null => (index >= len ? past : within);

const missingPreSide = (
  index: number,
  leftLen: number,
  rightLen: number
): number | null =>
  pastEnd(index, leftLen, -1, pastEnd(index, rightLen, 1, null));

const isDefinedPre = (
  value: string | number | undefined
): value is string | number => value !== undefined;

const definedPair = (
  left: string | number | undefined,
  right: string | number | undefined
): [string | number, string | number] | null => {
  if (isDefinedPre(left) && isDefinedPre(right)) {
    return [left, right];
  }
  return null;
};

const compareDefinedPre = (
  left: (string | number)[],
  right: (string | number)[],
  index: number
): number => {
  const ids = definedPair(left[index], right[index]);
  if (ids === null) {
    return 0;
  }
  const [da, db] = ids;
  return comparePreId(da, db);
};

const comparePreAt = (
  left: (string | number)[],
  right: (string | number)[],
  index: number
): number => {
  const missing = missingPreSide(index, left.length, right.length);
  return missing ?? compareDefinedPre(left, right, index);
};

const comparePre = (
  left: (string | number)[],
  right: (string | number)[]
): number => {
  const presence = prePresence(left.length, right.length);
  if (presence !== null) {
    return presence;
  }
  const len = Math.max(left.length, right.length);
  for (let i = 0; i < len; i += 1) {
    const cmp = comparePreAt(left, right, i);
    if (cmp !== 0) {
      return cmp;
    }
  }
  return 0;
};

const compareVersions = (left: string, right: string): number => {
  const a = parseSemver(left);
  const b = parseSemver(right);
  return compareCore(a.core, b.core) || comparePre(a.pre, b.pre);
};

const major = (version: string): string => {
  const match = version.match(/\d+/u);
  return match?.[0] ?? "";
};

const upgradeArgv = (
  manager: PackageManager,
  name: string,
  fix: string
): string[] | null => {
  switch (manager) {
    case "npm": {
      return ["npm", "install", `${name}@${fix}`, "--save-exact"];
    }
    case "pnpm": {
      return ["pnpm", "add", `${name}@${fix}`];
    }
    case "uv": {
      return ["uv", "lock", "--upgrade-package", name];
    }
    default: {
      return null;
    }
  }
};

const findingManager = (
  finding: Finding,
  project: Project
): PackageManager | undefined => {
  const manager =
    finding.manager ??
    project.managers.find((row) => row.role === "primary")?.name;
  if (manager === undefined || NON_UV_PYTHON.has(manager)) {
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
  if (!ADVISORY_KINDS.has(finding.kind) || finding.package === undefined) {
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

const mapSerial = async <T, R>(
  items: readonly T[],
  fn: (item: T) => Promise<R>
): Promise<R[]> => {
  const out: R[] = [];
  const runAt = async (index: number): Promise<void> => {
    if (index >= items.length) {
      return;
    }
    const item = items[index];
    if (item !== undefined) {
      out.push(await fn(item));
    }
    await runAt(index + 1);
  };
  await runAt(0);
  return out;
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
