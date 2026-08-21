import { createHash } from "node:crypto";
import path from "node:path";

import { auditAdvisories } from "./advisories";
import { APP_NAME, CONFIG_FILE_NAME } from "./app-name";
import { applyAdvisories } from "./apply-advisories";
import type { ApplyChoice, ApplyPrompt } from "./apply-advisories";
import { applySettings, applySettingsGroup } from "./apply-settings";
import type { ApplySettingsItem } from "./apply-settings";
import type { Cache } from "./cache";
import { CACHE_TTL_MS, createFsCache } from "./cache";
import { discoverProjects } from "./discover";
import type {
  ExitCode,
  Finding,
  PackageManager,
  Policy,
  PresetName,
  Project,
  Severity,
} from "./domain";
import { policyForRepo } from "./policy";
import type { PolicyLayers } from "./policy";
import { preflight } from "./preflight";
import { auditSettings } from "./settings";

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  info: 0,
  low: 1,
  moderate: 2,
};

const GATE_RANK: Record<PresetName, number> = {
  relaxed: SEVERITY_RANK.critical,
  standard: SEVERITY_RANK.high,
  strict: SEVERITY_RANK.moderate,
};

export interface AuditResult {
  exitCode: ExitCode;
  projects: { project: Project; findings: Finding[] }[];
  skippedDirty: string[];
}

export type AuditRun = (
  argv: string[],
  cwd: string
) => Promise<{ code: number; stdout: string; stderr: string }>;

export interface AuditPathInput {
  layers: PolicyLayers;
  apply: boolean;
  applyAdvisories: boolean;
  interactive: boolean;
  concurrency: number;
  force?: boolean;
  commit?: boolean;
  allowMajors?: boolean;
  refresh?: boolean;
  noCache?: boolean;
  deps: {
    readFile: (path: string) => string | null;
    readDir: (dir: string) => string[];
    isDir: (path: string) => boolean;
    which: (binary: string) => string | null;
    run: AuditRun;
    runOsv?: (lockOrRequirements: string) => Promise<Finding[]>;
    cache?: Cache;
    now?: () => number;
    digest?: (lockfileBytes: string) => string;
    writeFile?: (path: string, body: string) => void;
    gitStatus?: (root: string) => "clean" | "dirty" | "not-git";
    gitCommit?: (root: string, message: string, files: string[]) => boolean;
    prompt?: ApplyPrompt;
    currentVersions?: Record<string, string>;
    fixVersions?: Record<string, string>;
  };
}

interface AuditedProject {
  project: Project;
  findings: Finding[];
  projectPolicy: Policy;
  advisoryIncomplete: boolean;
}

const isIncomplete = (error: unknown): boolean =>
  typeof error === "object" && error !== null && "incomplete" in error;

const isAdvisoryKind = (kind: Finding["kind"]): boolean =>
  kind === "advisory" || kind === "deprecated" || kind === "quarantine";

const failsGate = (finding: Finding, gate: number): boolean => {
  if (finding.kind === "missing-binary") {
    return false;
  }
  if (finding.kind === "deprecated" || finding.kind === "quarantine") {
    return true;
  }
  return SEVERITY_RANK[finding.severity] >= gate;
};

const versionsFromFindings = (
  findings: Finding[],
  which: "current" | "fix"
): Record<string, string> => {
  const versions: Record<string, string> = {};
  for (const finding of findings) {
    if (finding.package === undefined) {
      continue;
    }
    const value =
      which === "current" ? finding.currentVersion : finding.fixVersion;
    if (value !== undefined) {
      versions[finding.package] = value;
    }
  }
  return versions;
};

export const defaultDigest = (lockfileBytes: string): string =>
  createHash("sha256").update(lockfileBytes).digest("hex");

const groupByGitRoot = (items: ApplySettingsItem[]): ApplySettingsItem[][] => {
  const groups = new Map<string, ApplySettingsItem[]>();
  for (const item of items) {
    const key = item.project.gitRoot ?? item.project.root;
    const group = groups.get(key) ?? [];
    group.push(item);
    groups.set(key, group);
  }
  return [...groups.values()];
};

const mapPool = async <T, R>(
  items: T[],
  concurrency: number,
  fn: (item: T) => Promise<R>
): Promise<R[]> => {
  const results: R[] = Array.from({ length: items.length });
  let next = 0;
  const runNext = async (): Promise<void> => {
    if (next >= items.length) {
      return;
    }
    const index = next;
    next += 1;
    const item = items[index];
    if (item !== undefined) {
      results[index] = await fn(item);
    }
    await runNext();
  };
  const size = Math.max(1, Math.min(concurrency, items.length || 1));
  await Promise.all(Array.from({ length: size }, () => runNext()));
  return results;
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

const projectGitRoot = (project: Project): string =>
  project.gitRoot ?? project.root;

const applySettingsForce = (
  input: AuditPathInput,
  appliedRoots: Set<string>,
  gitRoot: string
): boolean => (input.force ?? false) || appliedRoots.has(gitRoot);

const applyProjectSettings = (
  row: AuditedProject,
  input: AuditPathInput,
  appliedRoots: Set<string>
): boolean => {
  const { writeFile, gitStatus } = input.deps;
  if (writeFile === undefined || gitStatus === undefined) {
    return false;
  }
  const gitRoot = projectGitRoot(row.project);
  const applied = applySettings(row.project, row.findings, row.projectPolicy, {
    commit: input.commit ?? false,
    force: applySettingsForce(input, appliedRoots, gitRoot),
    gitCommit: input.deps.gitCommit,
    gitStatus,
    readFile: input.deps.readFile,
    writeFile,
  });
  if (applied.written.length > 0) {
    appliedRoots.add(gitRoot);
  }
  return applied.skipped === "dirty";
};

const shouldSkipDirty = (
  input: AuditPathInput,
  gitRoot: string,
  appliedRoots: Set<string>
): boolean => {
  const force = applySettingsForce(input, appliedRoots, gitRoot);
  const { gitStatus } = input.deps;
  return Boolean(gitStatus && !force && gitStatus(gitRoot) !== "clean");
};

const applyProjectAdvisories = async (
  row: AuditedProject,
  input: AuditPathInput,
  appliedRoots: Set<string>,
  allowMajors?: boolean
): Promise<boolean> => {
  const { deps } = input;
  const gitRoot = row.project.gitRoot ?? row.project.root;
  // A root we just wrote settings into is dirty by our own doing; still apply.
  if (shouldSkipDirty(input, gitRoot, appliedRoots)) {
    return true;
  }
  await applyAdvisories(row.project, row.findings, {
    allowMajors: allowMajors ?? input.allowMajors ?? false,
    currentVersions:
      deps.currentVersions ?? versionsFromFindings(row.findings, "current"),
    fixVersions: deps.fixVersions ?? versionsFromFindings(row.findings, "fix"),
    policy: row.projectPolicy,
    run: deps.run,
  });
  return false;
};

const applyChoice = async (
  row: AuditedProject,
  choice: ApplyChoice,
  input: AuditPathInput,
  appliedRoots: Set<string>
): Promise<boolean> => {
  let dirty = false;
  if (choice === "settings" || choice === "both") {
    dirty = applyProjectSettings(row, input, appliedRoots) || dirty;
  }
  if (choice === "advisories" || choice === "both") {
    dirty =
      (await applyProjectAdvisories(row, input, appliedRoots, true)) || dirty;
  }
  return dirty;
};

const runProjectAdvisories = async (
  project: Project,
  projectPolicy: Policy,
  missing: Set<PackageManager>,
  input: AuditPathInput,
  cache: Cache,
  now: () => number,
  digest: (lockfileBytes: string) => string
): Promise<{ findings: Finding[]; advisoryIncomplete: boolean }> => {
  try {
    const advisories = await auditAdvisories(
      {
        ...project,
        managers: project.managers.filter(
          (manager) => !missing.has(manager.name)
        ),
      },
      projectPolicy,
      {
        cache,
        digest,
        noCache: input.noCache,
        now,
        readFile: input.deps.readFile,
        refresh: input.refresh,
        run: input.deps.run,
        runOsv: input.deps.runOsv,
      }
    );
    return { advisoryIncomplete: false, findings: advisories.findings };
  } catch (error) {
    if (isIncomplete(error)) {
      return { advisoryIncomplete: true, findings: [] };
    }
    throw error;
  }
};

const auditOneProject = async (
  project: Project,
  input: AuditPathInput,
  cache: Cache,
  now: () => number,
  digest: (lockfileBytes: string) => string
): Promise<AuditedProject> => {
  const repoToml =
    input.deps.readFile(path.join(project.root, CONFIG_FILE_NAME)) ?? undefined;
  const projectPolicy = policyForRepo(input.layers, repoToml);
  const flight = preflight(project, { which: input.deps.which });
  const missing = new Set<PackageManager>(
    flight.missing.map((row) => row.manager)
  );
  const findings = [
    ...auditSettings(project, projectPolicy, { readFile: input.deps.readFile }),
    ...flight.warnings,
  ];
  const advisories = await runProjectAdvisories(
    project,
    projectPolicy,
    missing,
    input,
    cache,
    now,
    digest
  );
  findings.push(...advisories.findings);
  return {
    advisoryIncomplete: advisories.advisoryIncomplete,
    findings,
    project,
    projectPolicy,
  };
};

interface RecordedAudit {
  policyFailure: boolean;
  incomplete: boolean;
  projects: AuditResult["projects"];
  pendingApply: ApplySettingsItem[];
}

const recordAuditedRow = (
  row: AuditedProject,
  apply: boolean,
  deps: AuditPathInput["deps"],
  acc: RecordedAudit
): void => {
  if (row.advisoryIncomplete) {
    acc.incomplete = true;
  }
  const gate = GATE_RANK[row.projectPolicy.preset];
  if (row.findings.some((finding) => failsGate(finding, gate))) {
    acc.policyFailure = true;
  }
  acc.projects.push({ findings: row.findings, project: row.project });
  if (apply && deps.writeFile && deps.gitStatus) {
    acc.pendingApply.push({
      findings: row.findings,
      policy: row.projectPolicy,
      project: row.project,
    });
  }
};

const recordAudited = (
  audited: AuditedProject[],
  apply: boolean,
  deps: AuditPathInput["deps"]
): RecordedAudit => {
  const acc: RecordedAudit = {
    incomplete: false,
    pendingApply: [],
    policyFailure: false,
    projects: [],
  };
  for (const row of audited) {
    recordAuditedRow(row, apply, deps, acc);
  }
  return acc;
};

const promptCounts = (findings: Finding[]) => ({
  advisoryCount: findings.filter((finding) => isAdvisoryKind(finding.kind))
    .length,
  settingsCount: findings.filter((finding) => finding.kind === "settings")
    .length,
});

const applyInteractiveChoices = async (
  audited: AuditedProject[],
  prompt: ApplyPrompt,
  input: AuditPathInput
): Promise<Set<string>> => {
  const skippedDirty = new Set<string>();
  const appliedRoots = new Set<string>();
  await mapSerial(audited, async (row) => {
    const choice = await prompt({
      ...promptCounts(row.findings),
      project: row.project,
    });
    const dirty = await applyChoice(row, choice, input, appliedRoots);
    if (dirty) {
      skippedDirty.add(row.project.gitRoot ?? row.project.root);
    }
  });
  return skippedDirty;
};

const applyOneSettingsGroup = (
  group: ApplySettingsItem[],
  input: AuditPathInput,
  writeFile: (path: string, body: string) => void,
  gitStatus: (root: string) => "clean" | "dirty" | "not-git",
  appliedRoots: Set<string>,
  skippedDirty: Set<string>
): void => {
  const [first] = group;
  if (first === undefined) {
    return;
  }
  const applied = applySettingsGroup(group, {
    commit: input.commit ?? false,
    force: input.force ?? false,
    gitCommit: input.deps.gitCommit,
    gitStatus,
    readFile: input.deps.readFile,
    writeFile,
  });
  const gitRoot = first.project.gitRoot ?? first.project.root;
  if (applied.skipped === "dirty") {
    skippedDirty.add(gitRoot);
  }
  if (applied.written.length > 0) {
    appliedRoots.add(gitRoot);
  }
};

const applyGroupedSettings = (
  pendingApply: ApplySettingsItem[],
  input: AuditPathInput,
  appliedRoots: Set<string>,
  skippedDirty: Set<string>
): void => {
  const { writeFile, gitStatus } = input.deps;
  if (!(input.apply && writeFile && gitStatus)) {
    return;
  }
  for (const group of groupByGitRoot(pendingApply)) {
    applyOneSettingsGroup(
      group,
      input,
      writeFile,
      gitStatus,
      appliedRoots,
      skippedDirty
    );
  }
};

const applyAllAdvisories = async (
  audited: AuditedProject[],
  input: AuditPathInput,
  appliedRoots: Set<string>,
  skippedDirty: Set<string>
): Promise<void> => {
  if (!input.applyAdvisories) {
    return;
  }
  await mapSerial(audited, async (row) => {
    const dirty = await applyProjectAdvisories(row, input, appliedRoots);
    if (dirty) {
      skippedDirty.add(row.project.gitRoot ?? row.project.root);
    }
  });
};

const applyPhase = async (
  audited: AuditedProject[],
  pendingApply: ApplySettingsItem[],
  input: AuditPathInput
): Promise<Set<string>> => {
  const { prompt } = input.deps;
  if (input.interactive && prompt) {
    return applyInteractiveChoices(audited, prompt, input);
  }
  const skippedDirty = new Set<string>();
  const appliedRoots = new Set<string>();
  applyGroupedSettings(pendingApply, input, appliedRoots, skippedDirty);
  await applyAllAdvisories(audited, input, appliedRoots, skippedDirty);
  return skippedDirty;
};

const exitCodeFor = (
  projects: AuditResult["projects"],
  incomplete: boolean,
  skippedDirty: Set<string>,
  policyFailure: boolean
): ExitCode => {
  if (projects.length === 0 || incomplete || skippedDirty.size > 0) {
    return 2;
  }
  if (policyFailure) {
    return 1;
  }
  return 0;
};

export const auditPath = async (
  root: string,
  input: AuditPathInput
): Promise<AuditResult> => {
  const { deps } = input;
  const now = deps.now ?? Date.now;
  const digest = deps.digest ?? defaultDigest;
  const cache =
    deps.cache ??
    createFsCache(path.join(".cache", APP_NAME), now, CACHE_TTL_MS);
  const discovered = discoverProjects(root, {
    isDir: deps.isDir,
    readDir: deps.readDir,
    readFile: deps.readFile,
  });
  const concurrency = Math.max(1, input.concurrency);
  const audited = await mapPool(discovered, concurrency, (project) =>
    auditOneProject(project, input, cache, now, digest)
  );
  const recorded = recordAudited(audited, input.apply, deps);
  const skippedDirty = await applyPhase(audited, recorded.pendingApply, input);
  return {
    exitCode: exitCodeFor(
      recorded.projects,
      recorded.incomplete,
      skippedDirty,
      recorded.policyFailure
    ),
    projects: recorded.projects,
    skippedDirty: [...skippedDirty],
  };
};
