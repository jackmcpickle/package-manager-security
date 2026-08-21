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

export interface WriteDeps {
  writeFile: (path: string, body: string) => void;
  gitStatus: (root: string) => "clean" | "dirty" | "not-git";
  gitCommit?: (root: string, message: string, files: string[]) => boolean;
  force: boolean;
  commit: boolean;
}

export type AuditMode =
  | { kind: "audit" }
  | {
      kind: "apply";
      settings: boolean;
      advisories: boolean;
      allowMajors: boolean;
      write: WriteDeps;
    }
  | {
      kind: "interactive";
      prompt: ApplyPrompt;
      allowMajors: boolean;
      write: WriteDeps;
    };

export interface AuditPathInput {
  layers: PolicyLayers;
  mode: AuditMode;
  concurrency: number;
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
    digest: (lockfileBytes: string) => string;
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

interface ApplyPhaseResult {
  appliedRoots: Set<string>;
  skippedDirty: string[];
}

const emptyApplyResult = (): ApplyPhaseResult => ({
  appliedRoots: new Set(),
  skippedDirty: [],
});

const mergeApplyResult = (
  into: ApplyPhaseResult,
  from: ApplyPhaseResult
): ApplyPhaseResult => {
  for (const root of from.appliedRoots) {
    into.appliedRoots.add(root);
  }
  into.skippedDirty.push(...from.skippedDirty);
  return into;
};

const applySettingsForce = (
  write: WriteDeps,
  appliedRoots: Set<string>,
  gitRoot: string
): boolean => write.force || appliedRoots.has(gitRoot);

const applyProjectSettings = (
  row: AuditedProject,
  input: AuditPathInput,
  write: WriteDeps,
  appliedRoots: Set<string>
): ApplyPhaseResult => {
  const gitRoot = projectGitRoot(row.project);
  const applied = applySettings(row.project, row.findings, row.projectPolicy, {
    commit: write.commit,
    force: applySettingsForce(write, appliedRoots, gitRoot),
    gitCommit: write.gitCommit,
    gitStatus: write.gitStatus,
    readFile: input.deps.readFile,
    writeFile: write.writeFile,
  });
  return {
    appliedRoots: applied.written.length > 0 ? new Set([gitRoot]) : new Set(),
    skippedDirty: applied.skipped === "dirty" ? [gitRoot] : [],
  };
};

const shouldSkipDirty = (
  write: WriteDeps,
  gitRoot: string,
  appliedRoots: Set<string>
): boolean =>
  !applySettingsForce(write, appliedRoots, gitRoot) &&
  write.gitStatus(gitRoot) !== "clean";

const applyProjectAdvisories = async (
  row: AuditedProject,
  input: AuditPathInput,
  write: WriteDeps,
  appliedRoots: Set<string>,
  allowMajors: boolean
): Promise<ApplyPhaseResult> => {
  const { deps } = input;
  const gitRoot = row.project.gitRoot ?? row.project.root;
  // A root we just wrote settings into is dirty by our own doing; still apply.
  if (shouldSkipDirty(write, gitRoot, appliedRoots)) {
    return { appliedRoots: new Set(), skippedDirty: [gitRoot] };
  }
  await applyAdvisories(row.project, row.findings, {
    allowMajors,
    currentVersions:
      deps.currentVersions ?? versionsFromFindings(row.findings, "current"),
    fixVersions: deps.fixVersions ?? versionsFromFindings(row.findings, "fix"),
    policy: row.projectPolicy,
    run: deps.run,
  });
  return emptyApplyResult();
};

const applyChoice = async (
  row: AuditedProject,
  choice: ApplyChoice,
  input: AuditPathInput,
  write: WriteDeps,
  appliedRoots: Set<string>
): Promise<ApplyPhaseResult> => {
  const knownRoots = new Set(appliedRoots);
  const result = emptyApplyResult();
  if (choice === "settings" || choice === "both") {
    const settings = applyProjectSettings(row, input, write, knownRoots);
    mergeApplyResult(result, settings);
    for (const root of settings.appliedRoots) {
      knownRoots.add(root);
    }
  }
  if (choice === "advisories" || choice === "both") {
    mergeApplyResult(
      result,
      await applyProjectAdvisories(row, input, write, knownRoots, true)
    );
  }
  return result;
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
  shouldApplySettings: boolean,
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
  if (shouldApplySettings) {
    acc.pendingApply.push({
      findings: row.findings,
      policy: row.projectPolicy,
      project: row.project,
    });
  }
};

const recordAudited = (
  audited: AuditedProject[],
  shouldApplySettings: boolean
): RecordedAudit => {
  const acc: RecordedAudit = {
    incomplete: false,
    pendingApply: [],
    policyFailure: false,
    projects: [],
  };
  for (const row of audited) {
    recordAuditedRow(row, shouldApplySettings, acc);
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
  input: AuditPathInput,
  write: WriteDeps
): Promise<ApplyPhaseResult> => {
  const result = emptyApplyResult();
  await mapSerial(audited, async (row) => {
    const choice = await prompt({
      ...promptCounts(row.findings),
      project: row.project,
    });
    mergeApplyResult(
      result,
      await applyChoice(row, choice, input, write, result.appliedRoots)
    );
  });
  return result;
};

const applyOneSettingsGroup = (
  group: ApplySettingsItem[],
  input: AuditPathInput,
  write: WriteDeps
): ApplyPhaseResult => {
  const [first] = group;
  if (first === undefined) {
    return emptyApplyResult();
  }
  const applied = applySettingsGroup(group, {
    commit: write.commit,
    force: write.force,
    gitCommit: write.gitCommit,
    gitStatus: write.gitStatus,
    readFile: input.deps.readFile,
    writeFile: write.writeFile,
  });
  const gitRoot = first.project.gitRoot ?? first.project.root;
  return {
    appliedRoots: applied.written.length > 0 ? new Set([gitRoot]) : new Set(),
    skippedDirty: applied.skipped === "dirty" ? [gitRoot] : [],
  };
};

const applyGroupedSettings = (
  pendingApply: ApplySettingsItem[],
  input: AuditPathInput,
  write: WriteDeps
): ApplyPhaseResult => {
  const result = emptyApplyResult();
  for (const group of groupByGitRoot(pendingApply)) {
    mergeApplyResult(result, applyOneSettingsGroup(group, input, write));
  }
  return result;
};

const applyAllAdvisories = async (
  audited: AuditedProject[],
  input: AuditPathInput,
  write: WriteDeps,
  appliedRoots: Set<string>,
  allowMajors: boolean
): Promise<ApplyPhaseResult> => {
  const result = emptyApplyResult();
  await mapSerial(audited, async (row) => {
    mergeApplyResult(
      result,
      await applyProjectAdvisories(row, input, write, appliedRoots, allowMajors)
    );
  });
  return result;
};

const finalizeApply = (result: ApplyPhaseResult): ApplyPhaseResult => ({
  appliedRoots: result.appliedRoots,
  skippedDirty: [...new Set(result.skippedDirty)],
});

const applyPhase = async (
  audited: AuditedProject[],
  pendingApply: ApplySettingsItem[],
  input: AuditPathInput
): Promise<ApplyPhaseResult> => {
  const { mode } = input;
  if (mode.kind === "interactive") {
    return finalizeApply(
      await applyInteractiveChoices(audited, mode.prompt, input, mode.write)
    );
  }
  if (mode.kind !== "apply") {
    return emptyApplyResult();
  }
  const settings = mode.settings
    ? applyGroupedSettings(pendingApply, input, mode.write)
    : emptyApplyResult();
  const advisories = mode.advisories
    ? await applyAllAdvisories(
        audited,
        input,
        mode.write,
        settings.appliedRoots,
        mode.allowMajors
      )
    : emptyApplyResult();
  return finalizeApply(mergeApplyResult(settings, advisories));
};

const exitCodeFor = (
  projects: AuditResult["projects"],
  incomplete: boolean,
  skippedDirty: string[],
  policyFailure: boolean
): ExitCode => {
  if (projects.length === 0 || incomplete || skippedDirty.length > 0) {
    return 2;
  }
  if (policyFailure) {
    return 1;
  }
  return 0;
};

const shouldApplySettings = (mode: AuditMode): boolean =>
  mode.kind === "apply" && mode.settings;

export const auditPath = async (
  root: string,
  input: AuditPathInput
): Promise<AuditResult> => {
  const { deps } = input;
  const now = deps.now ?? Date.now;
  const { digest } = deps;
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
  const recorded = recordAudited(audited, shouldApplySettings(input.mode));
  const applied = await applyPhase(audited, recorded.pendingApply, input);
  return {
    exitCode: exitCodeFor(
      recorded.projects,
      recorded.incomplete,
      applied.skippedDirty,
      recorded.policyFailure
    ),
    projects: recorded.projects,
    skippedDirty: applied.skippedDirty,
  };
};
