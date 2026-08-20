import { createHash } from "node:crypto";
import { join } from "node:path";
import { parse } from "smol-toml";
import { auditAdvisories } from "./advisories";
import { applyAdvisories, type ApplyChoice, type ApplyPrompt } from "./apply-advisories";
import { applySettings, applySettingsGroup, type ApplySettingsItem } from "./apply-settings";
import type { Cache } from "./cache";
import { CACHE_TTL_MS, createFsCache } from "./cache";
import { discoverProjects } from "./discover";
import type { ExitCode, Finding, PackageManager, Policy, PresetName, Project, Severity } from "./domain";
import { loadPolicy } from "./policy";
import { preflight } from "./preflight";
import { auditSettings } from "./settings";

const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  moderate: 2,
  high: 3,
  critical: 4,
};

const GATE_RANK: Record<PresetName, number> = {
  relaxed: SEVERITY_RANK.critical,
  standard: SEVERITY_RANK.high,
  strict: SEVERITY_RANK.moderate,
};

export type AuditResult = {
  exitCode: ExitCode;
  projects: Array<{ project: Project; findings: Finding[] }>;
  skippedDirty: string[];
};

export type AuditRun = (
  argv: string[],
  cwd: string,
) => Promise<{ code: number; stdout: string; stderr: string }>;

export async function auditPath(
  root: string,
  input: {
    policy: Policy;
    apply: boolean;
    applyAdvisories: boolean;
    interactive: boolean;
    concurrency: number;
    flags?: { preset?: PresetName; overrides?: Record<string, unknown> };
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
  },
): Promise<AuditResult> {
  const { policy, apply, deps, flags } = input;
  const now = deps.now ?? Date.now;
  const digest = deps.digest ?? defaultDigest;
  const cache = deps.cache ?? createFsCache(join(".cache", "pmsec"), now, CACHE_TTL_MS);
  const discovered = discoverProjects(root, {
    readFile: deps.readFile,
    readDir: deps.readDir,
    isDir: deps.isDir,
  });

  let policyFailure = false;
  let incomplete = false;
  const skippedDirty = new Set<string>();
  const projects: AuditResult["projects"] = [];
  const pendingApply: ApplySettingsItem[] = [];
  const concurrency = Math.max(1, input.concurrency);

  const audited = await mapPool(discovered, concurrency, async (project) => {
    const repoToml = deps.readFile(join(project.root, ".pmsec.toml")) ?? undefined;
    const projectPolicy = overlayRepoPolicy(policy, repoToml, flags);
    const flight = preflight(project, { which: deps.which });
    const missing = new Set<PackageManager>(flight.missing.map((row) => row.manager));
    const findings = [
      ...auditSettings(project, projectPolicy, { readFile: deps.readFile }),
      ...flight.warnings,
    ];

    let advisoryIncomplete = false;
    try {
      const advisoryProject = {
        ...project,
        managers: project.managers.filter((manager) => !missing.has(manager.name)),
      };
      const advisories = await auditAdvisories(advisoryProject, projectPolicy, {
        cache,
        now,
        digest,
        readFile: deps.readFile,
        run: deps.run,
        runOsv: deps.runOsv,
        refresh: input.refresh,
        noCache: input.noCache,
      });
      findings.push(...advisories.findings);
    } catch (error) {
      if (isIncomplete(error)) advisoryIncomplete = true;
      else throw error;
    }

    return { project, findings, projectPolicy, advisoryIncomplete };
  });

  for (const row of audited) {
    if (row.advisoryIncomplete) incomplete = true;
    const gate = GATE_RANK[row.projectPolicy.preset];
    if (row.findings.some((finding) => failsGate(finding, gate))) policyFailure = true;
    projects.push({ project: row.project, findings: row.findings });
    if (apply && deps.writeFile && deps.gitStatus) {
      pendingApply.push({
        project: row.project,
        findings: row.findings,
        policy: row.projectPolicy,
      });
    }
  }

  const prompt = deps.prompt;
  if (input.interactive && prompt) {
    const appliedRoots = new Set<string>();
    for (const row of audited) {
      const choice = await prompt({
        project: row.project,
        settingsCount: row.findings.filter((finding) => finding.kind === "settings").length,
        advisoryCount: row.findings.filter((finding) => isAdvisoryKind(finding.kind)).length,
      });
      const dirty = await applyChoice(row, choice, input, appliedRoots);
      if (dirty) skippedDirty.add(row.project.gitRoot ?? row.project.root);
    }
  } else {
    const appliedRoots = new Set<string>();
    if (apply && deps.writeFile && deps.gitStatus) {
      for (const group of groupByGitRoot(pendingApply)) {
        const applied = applySettingsGroup(group, {
          readFile: deps.readFile,
          writeFile: deps.writeFile,
          gitStatus: deps.gitStatus,
          gitCommit: deps.gitCommit,
          force: input.force ?? false,
          commit: input.commit ?? false,
        });
        if (applied.skipped === "dirty") {
          skippedDirty.add(group[0]!.project.gitRoot ?? group[0]!.project.root);
        }
        if (applied.written.length > 0) {
          appliedRoots.add(group[0]!.project.gitRoot ?? group[0]!.project.root);
        }
      }
    }
    if (input.applyAdvisories) {
      for (const row of audited) {
        const dirty = await applyProjectAdvisories(row, input, appliedRoots);
        if (dirty) skippedDirty.add(row.project.gitRoot ?? row.project.root);
      }
    }
  }

  let exitCode: ExitCode = 0;
  if (projects.length === 0 || incomplete || skippedDirty.size > 0) exitCode = 2;
  else if (policyFailure) exitCode = 1;

  return { exitCode, projects, skippedDirty: [...skippedDirty] };
}

type AuditedProject = {
  project: Project;
  findings: Finding[];
  projectPolicy: Policy;
  advisoryIncomplete: boolean;
};

async function applyChoice(
  row: AuditedProject,
  choice: ApplyChoice,
  input: Parameters<typeof auditPath>[1],
  appliedRoots: Set<string>,
): Promise<boolean> {
  let dirty = false;
  if (choice === "settings" || choice === "both") {
    dirty = applyProjectSettings(row, input, appliedRoots) || dirty;
  }
  if (choice === "advisories" || choice === "both") {
    dirty = (await applyProjectAdvisories(row, input, appliedRoots, true)) || dirty;
  }
  return dirty;
}

function applyProjectSettings(
  row: AuditedProject,
  input: Parameters<typeof auditPath>[1],
  appliedRoots: Set<string>,
): boolean {
  const { deps } = input;
  if (!deps.writeFile || !deps.gitStatus) return false;
  const gitRoot = row.project.gitRoot ?? row.project.root;
  const applied = applySettings(row.project, row.findings, row.projectPolicy, {
    readFile: deps.readFile,
    writeFile: deps.writeFile,
    gitStatus: deps.gitStatus,
    gitCommit: deps.gitCommit,
    force: (input.force ?? false) || appliedRoots.has(gitRoot),
    commit: input.commit ?? false,
  });
  if (applied.written.length > 0) appliedRoots.add(gitRoot);
  return applied.skipped === "dirty";
}

async function applyProjectAdvisories(
  row: AuditedProject,
  input: Parameters<typeof auditPath>[1],
  appliedRoots: Set<string>,
  allowMajors?: boolean,
): Promise<boolean> {
  const { deps } = input;
  const gitRoot = row.project.gitRoot ?? row.project.root;
  // A root we just wrote settings into is dirty by our own doing; still apply.
  const force = (input.force ?? false) || appliedRoots.has(gitRoot);
  if (deps.gitStatus && !force && deps.gitStatus(gitRoot) !== "clean") {
    return true;
  }
  await applyAdvisories(row.project, row.findings, {
    run: deps.run,
    allowMajors: allowMajors ?? input.allowMajors ?? false,
    currentVersions: deps.currentVersions ?? versionsFromFindings(row.findings, "current"),
    fixVersions: deps.fixVersions ?? versionsFromFindings(row.findings, "fix"),
    policy: row.projectPolicy,
  });
  return false;
}

function versionsFromFindings(
  findings: Finding[],
  which: "current" | "fix",
): Record<string, string> {
  const versions: Record<string, string> = {};
  for (const finding of findings) {
    if (finding.package === undefined) continue;
    const value = which === "current" ? finding.currentVersion : finding.fixVersion;
    if (value !== undefined) versions[finding.package] = value;
  }
  return versions;
}

function isAdvisoryKind(kind: Finding["kind"]): boolean {
  return kind === "advisory" || kind === "deprecated" || kind === "quarantine";
}

async function mapPool<T, R>(items: T[], concurrency: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const index = next;
      next += 1;
      results[index] = await fn(items[index]!);
    }
  };
  const size = Math.max(1, Math.min(concurrency, items.length || 1));
  await Promise.all(Array.from({ length: size }, () => worker()));
  return results;
}

export function defaultDigest(lockfileBytes: string): string {
  return createHash("sha256").update(lockfileBytes).digest("hex");
}

function overlayRepoPolicy(
  base: Policy,
  repoToml: string | undefined,
  flags?: { preset?: PresetName; overrides?: Record<string, unknown> },
): Policy {
  if (repoToml === undefined) return base;
  const repo = loadPolicy({ repoToml });
  let parsed: unknown;
  try {
    parsed = parse(repoToml);
  } catch {
    parsed = {};
  }
  const keys = isPlainObject(parsed) ? parsed : {};
  const flagOverrides = flags?.overrides ?? {};
  const perManager: Policy["perManager"] = { ...base.perManager };
  for (const [name, table] of Object.entries(repo.perManager)) {
    const key = name as keyof Policy["perManager"];
    perManager[key] = { ...perManager[key], ...table, ...flagOverrides };
  }
  return {
    preset: flags?.preset ?? (typeof keys.preset === "string" ? repo.preset : base.preset),
    enabledManagers: Array.isArray(keys.enabledManagers)
      ? repo.enabledManagers
      : base.enabledManagers,
    overrides: { ...base.overrides, ...repo.overrides, ...flagOverrides },
    perManager,
  };
}

function failsGate(finding: Finding, gate: number): boolean {
  if (finding.kind === "missing-binary") return false;
  if (finding.kind === "deprecated" || finding.kind === "quarantine") return true;
  return SEVERITY_RANK[finding.severity] >= gate;
}

function isIncomplete(error: unknown): boolean {
  return typeof error === "object" && error !== null && "incomplete" in error;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function groupByGitRoot(items: ApplySettingsItem[]): ApplySettingsItem[][] {
  const groups = new Map<string, ApplySettingsItem[]>();
  for (const item of items) {
    const key = item.project.gitRoot ?? item.project.root;
    const group = groups.get(key) ?? [];
    group.push(item);
    groups.set(key, group);
  }
  return [...groups.values()];
}
