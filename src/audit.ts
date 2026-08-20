import { createHash } from "node:crypto";
import { join } from "node:path";
import { parse } from "smol-toml";
import { auditAdvisories } from "./advisories";
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
  const projects: AuditResult["projects"] = [];

  for (const project of discovered) {
    const repoToml = deps.readFile(join(project.root, ".pmsec.toml")) ?? undefined;
    const projectPolicy = overlayRepoPolicy(policy, repoToml, flags);
    const flight = preflight(project, { which: deps.which });
    const missing = new Set<PackageManager>(flight.missing.map((row) => row.manager));
    const findings = [
      ...auditSettings(project, projectPolicy, { readFile: deps.readFile }),
      ...flight.warnings,
    ];

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
      });
      findings.push(...advisories.findings);
    } catch (error) {
      if (isIncomplete(error)) incomplete = true;
      else throw error;
    }

    const gate = GATE_RANK[projectPolicy.preset];
    if (findings.some((finding) => failsGate(finding, gate))) policyFailure = true;
    projects.push({ project, findings });
  }

  let exitCode: ExitCode = 0;
  if (projects.length === 0 || apply || incomplete) exitCode = 2;
  else if (policyFailure) exitCode = 1;

  return { exitCode, projects };
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
  return SEVERITY_RANK[finding.severity] >= gate;
}

function isIncomplete(error: unknown): boolean {
  return typeof error === "object" && error !== null && "incomplete" in error;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
