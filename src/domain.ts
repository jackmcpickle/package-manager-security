export type PackageManager =
  | "npm"
  | "pnpm"
  | "yarn"
  | "bun"
  | "uv"
  | "cargo"
  | "poetry"
  | "pip"
  | "pipenv"
  | "bundler";

export type PresetName = "relaxed" | "standard" | "strict";

export type Severity = "critical" | "high" | "moderate" | "low" | "info";

export type FindingKind =
  | "settings"
  | "advisory"
  | "leftover-lockfile"
  | "unsupported-pm"
  | "missing-binary"
  | "not-using-uv"
  | "deprecated"
  | "quarantine";

export type ManagerRole = "primary" | "leftover" | "unsupported";

export interface DetectedManager {
  name: PackageManager;
  role: ManagerRole;
  manifestPath: string;
  lockfilePath: string | null;
  configPath: string | null;
}

export interface Project {
  root: string;
  gitRoot: string | null;
  managers: DetectedManager[];
}

export interface Finding {
  kind: FindingKind;
  code: string;
  message: string;
  severity: Severity;
  path: string;
  fixable: boolean;
  manager?: PackageManager;
  package?: string;
  currentVersion?: string;
  fixVersion?: string;
}

export interface Policy {
  preset: PresetName;
  enabledManagers: PackageManager[];
  overrides: Record<string, unknown>;
  perManager: Partial<Record<PackageManager, Record<string, unknown>>>;
}

export type ExitCode = 0 | 1 | 2;
