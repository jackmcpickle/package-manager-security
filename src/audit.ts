import { join } from "node:path";
import { parse } from "smol-toml";
import { discoverProjects } from "./discover";
import type { ExitCode, Finding, Policy, PresetName, Project, Severity } from "./domain";
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

export function auditPath(
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
    };
  },
): { exitCode: ExitCode; projects: Array<{ project: Project; findings: Finding[] }> } {
  const { policy, apply, deps, flags } = input;
  const discovered = discoverProjects(root, {
    readFile: deps.readFile,
    readDir: deps.readDir,
    isDir: deps.isDir,
  });

  let policyFailure = false;
  const projects = discovered.map((project) => {
    const repoToml = deps.readFile(join(project.root, ".pmsec.toml")) ?? undefined;
    const projectPolicy = overlayRepoPolicy(policy, repoToml, flags);
    const findings = [
      ...auditSettings(project, projectPolicy, { readFile: deps.readFile }),
      ...preflight(project, { which: deps.which }).warnings,
    ];
    const gate = GATE_RANK[projectPolicy.preset];
    if (findings.some((finding) => failsGate(finding, gate))) policyFailure = true;
    return { project, findings };
  });

  let exitCode: ExitCode = 0;
  if (projects.length === 0 || apply) exitCode = 2;
  else if (policyFailure) exitCode = 1;

  return { exitCode, projects };
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

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
