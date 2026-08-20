import { readFileSync } from "node:fs";
import type {
  DetectedManager,
  Finding,
  PackageManager,
  Policy,
  PresetName,
  Project,
  Severity,
} from "./domain";
import { PRESET_DEFAULTS } from "./policy";

export type SettingsFs = {
  readFile?: (path: string) => string | null;
};

type ReadFile = (path: string) => string | null;

type ResolvedSettings = {
  ignoreScripts: boolean;
  minReleaseAgeDays: number;
  auditLevel: string;
  requireLockfile: boolean;
  requirePmPin: boolean;
};

const AUDIT_RANK: Record<string, number> = {
  info: 0,
  low: 1,
  moderate: 2,
  high: 3,
  critical: 4,
};

export function auditSettings(
  project: Project,
  policy: Policy,
  opts?: SettingsFs,
): Finding[] {
  const readFile = opts?.readFile ?? defaultReadFile;
  const findings: Finding[] = [];

  for (const manager of project.managers) {
    if (manager.role === "leftover") {
      findings.push(leftoverFinding(manager));
      continue;
    }
    if (manager.role !== "primary") continue;
    if (!policy.enabledManagers.includes(manager.name)) continue;

    if (manager.name === "npm") {
      findings.push(...auditNpm(project, manager, policy, readFile));
    } else if (manager.name === "pnpm") {
      findings.push(...auditPnpm(project, manager, policy, readFile));
    }
  }

  return findings;
}

function leftoverFinding(manager: DetectedManager): Finding {
  return {
    kind: "leftover-lockfile",
    code: "lockfile.leftover",
    message: `Leftover ${manager.name} lockfile is not an apply target`,
    severity: "high",
    path: manager.lockfilePath ?? manager.manifestPath,
    fixable: false,
    manager: manager.name,
  };
}

function auditNpm(
  project: Project,
  manager: DetectedManager,
  policy: Policy,
  readFile: ReadFile,
): Finding[] {
  const settings = resolveSettings(policy, "npm");
  const npmrcPath = manager.configPath ?? `${project.root}/.npmrc`;
  const npmrc = parseNpmrc(readFile(npmrcPath) ?? "");
  const findings: Finding[] = [];

  if (settings.ignoreScripts && npmrc["ignore-scripts"] !== "true") {
    findings.push(
      setting(
        "scripts.unrestricted",
        "npm ignore-scripts must be true",
        "high",
        npmrcPath,
        "npm",
      ),
    );
  }

  if (settings.requireLockfile && !lockfilePresent(manager, readFile, `${project.root}/package-lock.json`)) {
    findings.push(
      setting(
        "lockfile.missing",
        "package-lock.json is required",
        "high",
        manager.lockfilePath ?? `${project.root}/package-lock.json`,
        "npm",
      ),
    );
  }

  if (!auditMeetsGate(npmrc["audit"] === "true", npmrc["audit-level"], settings.auditLevel)) {
    findings.push(
      setting(
        "audit.disabled",
        "npm audit must be enabled at the preset gate",
        "high",
        npmrcPath,
        "npm",
      ),
    );
  }

  if (settings.minReleaseAgeDays > 0) {
    const days = parseNumber(npmrc["min-release-age"]);
    if (days === null || days < settings.minReleaseAgeDays) {
      findings.push(
        setting(
          "min-age.disabled",
          `min-release-age must be at least ${settings.minReleaseAgeDays} days`,
          "high",
          npmrcPath,
          "npm",
        ),
      );
    }
  }

  if (!hasText(npmrc["registry"])) {
    findings.push(
      setting(
        "registry.unpinned",
        "registry must be set in .npmrc",
        pinSeverity(policy.preset),
        npmrcPath,
        "npm",
      ),
    );
  }

  if (settings.requirePmPin && !packageManagerStartsWith(readFile(manager.manifestPath), "npm@")) {
    findings.push(
      setting(
        "pm.unpinned",
        "package.json packageManager must start with npm@",
        pinSeverity(policy.preset),
        manager.manifestPath,
        "npm",
      ),
    );
  }

  return findings;
}

function auditPnpm(
  project: Project,
  manager: DetectedManager,
  policy: Policy,
  readFile: ReadFile,
): Finding[] {
  const settings = resolveSettings(policy, "pnpm");
  const yamlPath = manager.configPath ?? `${project.root}/pnpm-workspace.yaml`;
  const yaml = parseYaml(readFile(yamlPath) ?? "");
  const findings: Finding[] = [];

  if (settings.ignoreScripts) {
    const allowAll = yaml["dangerouslyAllowAllBuilds"] === true;
    const hasAllowlist =
      yaml["onlyBuiltDependencies"] !== undefined ||
      yaml["neverBuiltDependencies"] !== undefined;
    if (allowAll || !hasAllowlist) {
      findings.push(
        setting(
          "scripts.unrestricted",
          "pnpm builds must be restricted",
          "high",
          yamlPath,
          "pnpm",
        ),
      );
    }
  }

  const lockfileOff = yaml["lockfile"] === false;
  if (
    settings.requireLockfile &&
    (lockfileOff || !lockfilePresent(manager, readFile, `${project.root}/pnpm-lock.yaml`))
  ) {
    findings.push(
      setting(
        "lockfile.missing",
        "pnpm-lock.yaml is required",
        "high",
        manager.lockfilePath ?? `${project.root}/pnpm-lock.yaml`,
        "pnpm",
      ),
    );
  }

  if (!auditMeetsGate(isTruthy(yaml["audit"]), yaml["auditLevel"] ?? yaml["audit-level"], settings.auditLevel)) {
    findings.push(
      setting(
        "audit.disabled",
        "pnpm audit must be enabled at the preset gate",
        "high",
        yamlPath,
        "pnpm",
      ),
    );
  }

  if (settings.minReleaseAgeDays > 0) {
    const hours = parsePnpmAgeHours(yaml["minimumReleaseAge"]);
    const requiredHours = settings.minReleaseAgeDays * 24;
    if (hours === null || hours < requiredHours) {
      findings.push(
        setting(
          "min-age.disabled",
          `minimumReleaseAge must be at least ${requiredHours} hours`,
          "high",
          yamlPath,
          "pnpm",
        ),
      );
    }
  }

  if (!pnpmRegistryPinned(yaml)) {
    findings.push(
      setting(
        "registry.unpinned",
        "registry or registries.default must be set",
        pinSeverity(policy.preset),
        yamlPath,
        "pnpm",
      ),
    );
  }

  if (settings.requirePmPin && !packageManagerStartsWith(readFile(manager.manifestPath), "pnpm@")) {
    findings.push(
      setting(
        "pm.unpinned",
        "package.json packageManager must start with pnpm@",
        pinSeverity(policy.preset),
        manager.manifestPath,
        "pnpm",
      ),
    );
  }

  return findings;
}

function setting(
  code: string,
  message: string,
  severity: Severity,
  path: string,
  manager: PackageManager,
): Finding {
  return {
    kind: "settings",
    code,
    message,
    severity,
    path,
    fixable: true,
    manager,
  };
}

function resolveSettings(policy: Policy, name: PackageManager): ResolvedSettings {
  const base = PRESET_DEFAULTS[policy.preset];
  const extra = { ...policy.overrides, ...policy.perManager[name] };
  return {
    ignoreScripts:
      typeof extra.ignoreScripts === "boolean" ? extra.ignoreScripts : base.ignoreScripts,
    minReleaseAgeDays:
      typeof extra.minReleaseAgeDays === "number"
        ? extra.minReleaseAgeDays
        : base.minReleaseAgeDays,
    auditLevel: typeof extra.auditLevel === "string" ? extra.auditLevel : base.auditLevel,
    requireLockfile:
      typeof extra.requireLockfile === "boolean" ? extra.requireLockfile : base.requireLockfile,
    requirePmPin:
      typeof extra.requirePmPin === "boolean" ? extra.requirePmPin : base.requirePmPin,
  };
}

function pinSeverity(preset: PresetName): Severity {
  return preset === "strict" ? "high" : "info";
}

function lockfilePresent(
  manager: DetectedManager,
  readFile: ReadFile,
  fallback: string,
): boolean {
  const path = manager.lockfilePath ?? fallback;
  return readFile(path) !== null;
}

function auditMeetsGate(
  auditEnabled: boolean,
  auditLevel: unknown,
  gate: string,
): boolean {
  if (auditEnabled) return true;
  const level = typeof auditLevel === "string" ? auditLevel.toLowerCase() : "";
  const have = AUDIT_RANK[level];
  const need = AUDIT_RANK[gate] ?? AUDIT_RANK.high;
  return have !== undefined && need !== undefined && have <= need;
}

function packageManagerStartsWith(raw: string | null, prefix: string): boolean {
  if (raw === null) return false;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!isPlainObject(parsed)) return false;
    return typeof parsed.packageManager === "string" && parsed.packageManager.startsWith(prefix);
  } catch {
    return false;
  }
}

function parseNpmrc(raw: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed === "" || trimmed.startsWith("#") || trimmed.startsWith(";")) continue;
    const eq = trimmed.indexOf("=");
    if (eq <= 0) continue;
    const key = trimmed.slice(0, eq).trim();
    const value = trimmed.slice(eq + 1).trim();
    out[key] = value;
  }
  return out;
}

function parseYaml(raw: string): Record<string, unknown> {
  if (raw.trim() === "") return {};
  try {
    const parsed: unknown = Bun.YAML.parse(raw);
    return isPlainObject(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function pnpmRegistryPinned(yaml: Record<string, unknown>): boolean {
  if (hasText(yaml["registry"])) return true;
  const registries = yaml["registries"];
  if (!isPlainObject(registries)) return false;
  return hasText(registries["default"]);
}

function parsePnpmAgeHours(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value !== "string") return null;
  const trimmed = value.trim().toLowerCase();
  const match = trimmed.match(
    /^(\d+(?:\.\d+)?)\s*(m|min|mins|minutes|h|hr|hrs|hours|d|day|days|w|week|weeks)?$/,
  );
  if (!match) return parseNumber(trimmed);
  const amount = Number(match[1]);
  if (!Number.isFinite(amount)) return null;
  const unit = match[2] ?? "h";
  if (unit.startsWith("w")) return amount * 24 * 7;
  if (unit.startsWith("d")) return amount * 24;
  if (unit.startsWith("m")) return amount / 60;
  return amount;
}

function parseNumber(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value !== "string") return null;
  const n = Number(value.trim());
  return Number.isFinite(n) ? n : null;
}

function isTruthy(value: unknown): boolean {
  return value === true || value === "true";
}

function hasText(value: unknown): boolean {
  return typeof value === "string" && value.trim() !== "";
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function defaultReadFile(path: string): string | null {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
}
