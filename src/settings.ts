import { readFileSync } from "node:fs";
import { parse as parseTomlRaw } from "smol-toml";
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
    if (manager.role === "unsupported") {
      findings.push(unsupportedFinding(manager));
      continue;
    }
    if (manager.role !== "primary") continue;
    if (manager.name === "poetry" || manager.name === "pip" || manager.name === "pipenv") {
      findings.push(notUsingUvFinding(manager));
      continue;
    }
    if (!policy.enabledManagers.includes(manager.name)) continue;

    if (manager.name === "npm") {
      findings.push(...auditNpm(project, manager, policy, readFile));
    } else if (manager.name === "pnpm") {
      findings.push(...auditPnpm(project, manager, policy, readFile));
    } else if (manager.name === "yarn") {
      findings.push(...auditYarn(project, manager, policy, readFile));
    } else if (manager.name === "bun") {
      findings.push(...auditBun(project, manager, policy, readFile));
    } else if (manager.name === "uv") {
      findings.push(...auditUv(project, manager, policy, readFile));
    }
  }

  return findings;
}

function notUsingUvFinding(manager: DetectedManager): Finding {
  return {
    kind: "not-using-uv",
    code: "python.not-uv",
    message: `${manager.name} project is not using uv`,
    severity: "high",
    path: manager.lockfilePath ?? manager.manifestPath,
    fixable: false,
    manager: manager.name,
  };
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

function unsupportedFinding(manager: DetectedManager): Finding {
  return {
    kind: "unsupported-pm",
    code: "pm.unsupported",
    message: `${manager.name} is unsupported`,
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
          `minimumReleaseAge must be at least ${requiredHours * 60} minutes`,
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

function auditYarn(
  project: Project,
  manager: DetectedManager,
  policy: Policy,
  readFile: ReadFile,
): Finding[] {
  const settings = resolveSettings(policy, "yarn");
  const yarnrcPath = manager.configPath ?? `${project.root}/.yarnrc.yml`;
  const yarnrc = parseYaml(readFile(yarnrcPath) ?? "");
  const findings: Finding[] = [];

  if (settings.ignoreScripts && yarnrc["enableScripts"] !== false) {
    findings.push(
      setting(
        "scripts.unrestricted",
        "yarn enableScripts must be false",
        "high",
        yarnrcPath,
        "yarn",
      ),
    );
  }

  if (settings.requireLockfile && !lockfilePresent(manager, readFile, `${project.root}/yarn.lock`)) {
    findings.push(
      setting(
        "lockfile.missing",
        "yarn.lock is required",
        "high",
        manager.lockfilePath ?? `${project.root}/yarn.lock`,
        "yarn",
      ),
    );
  }

  if (yarnAuditDisabled(yarnrc)) {
    findings.push(
      setting(
        "audit.disabled",
        "yarn audit must not be disabled",
        "high",
        yarnrcPath,
        "yarn",
      ),
    );
  }

  if (!hasText(yarnrc["npmRegistryServer"])) {
    findings.push(
      setting(
        "registry.unpinned",
        "npmRegistryServer must be set",
        pinSeverity(policy.preset),
        yarnrcPath,
        "yarn",
      ),
    );
  }

  if (settings.requirePmPin && !packageManagerYarnBerry(readFile(manager.manifestPath))) {
    findings.push(
      setting(
        "pm.unpinned",
        "package.json packageManager must be yarn@ major >= 2",
        pinSeverity(policy.preset),
        manager.manifestPath,
        "yarn",
      ),
    );
  }

  return findings;
}

function auditBun(
  project: Project,
  manager: DetectedManager,
  policy: Policy,
  readFile: ReadFile,
): Finding[] {
  const settings = resolveSettings(policy, "bun");
  const bunfigPath = manager.configPath ?? `${project.root}/bunfig.toml`;
  const bunfig = parseToml(readFile(bunfigPath) ?? "");
  const install = isPlainObject(bunfig["install"]) ? bunfig["install"] : {};
  const findings: Finding[] = [];

  if (settings.ignoreScripts && bunScriptsUnrestricted(bunfig, install)) {
    findings.push(
      setting(
        "scripts.unrestricted",
        "bun scripts must be restricted",
        "high",
        bunfigPath,
        "bun",
      ),
    );
  }

  if (settings.requireLockfile && !bunLockfilePresent(project, manager, readFile)) {
    findings.push(
      setting(
        "lockfile.missing",
        "bun.lock or bun.lockb is required",
        "high",
        manager.lockfilePath ?? `${project.root}/bun.lock`,
        "bun",
      ),
    );
  }

  if (!bunRegistryPinned(install)) {
    findings.push(
      setting(
        "registry.unpinned",
        "install.registry must be set",
        pinSeverity(policy.preset),
        bunfigPath,
        "bun",
      ),
    );
  }

  return findings;
}

function auditUv(
  project: Project,
  manager: DetectedManager,
  policy: Policy,
  readFile: ReadFile,
): Finding[] {
  const settings = resolveSettings(policy, "uv");
  const cfg = readUvConfig(project, readFile);
  const configPath = manager.configPath ?? `${project.root}/pyproject.toml`;
  const findings: Finding[] = [];

  if (settings.requireLockfile && !lockfilePresent(manager, readFile, `${project.root}/uv.lock`)) {
    findings.push(
      setting(
        "lockfile.missing",
        "uv.lock is required",
        "high",
        manager.lockfilePath ?? `${project.root}/uv.lock`,
        "uv",
      ),
    );
  }

  if (settings.minReleaseAgeDays > 0 && !uvExcludeNewerMeets(cfg["exclude-newer"], settings.minReleaseAgeDays)) {
    findings.push(
      setting(
        "min-age.disabled",
        `exclude-newer must meet ${settings.minReleaseAgeDays} days`,
        "high",
        configPath,
        "uv",
      ),
    );
  }

  if (policy.preset === "strict" && uvHasExtraIndexes(cfg) && cfg["index-strategy"] !== "first-index") {
    findings.push(
      setting(
        "registry.unpinned",
        'extra indexes require index-strategy = "first-index"',
        pinSeverity(policy.preset),
        configPath,
        "uv",
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
  // pnpm treats bare minimumReleaseAge numbers as MINUTES.
  if (typeof value === "number" && Number.isFinite(value)) return value / 60;
  if (typeof value !== "string") return null;
  const trimmed = value.trim().toLowerCase();
  const match = trimmed.match(
    /^(\d+(?:\.\d+)?)\s*(m|min|mins|minutes|h|hr|hrs|hours|d|day|days|w|week|weeks)?$/,
  );
  if (!match) {
    const bare = parseNumber(trimmed);
    return bare === null ? null : bare / 60;
  }
  const amount = Number(match[1]);
  if (!Number.isFinite(amount)) return null;
  const unit = match[2] ?? "m";
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

function yarnAuditDisabled(yarnrc: Record<string, unknown>): boolean {
  return (
    yarnrc["audit"] === false ||
    yarnrc["npmAudit"] === false ||
    yarnrc["enableNpmAudit"] === false
  );
}

function packageManagerYarnBerry(raw: string | null): boolean {
  if (raw === null) return false;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!isPlainObject(parsed)) return false;
    const field = parsed.packageManager;
    if (typeof field !== "string") return false;
    const match = field.match(
      /^yarn@(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/,
    );
    if (match === null) return false;
    return Number(match[1]) >= 2;
  } catch {
    return false;
  }
}

function bunScriptsUnrestricted(
  bunfig: Record<string, unknown>,
  install: Record<string, unknown>,
): boolean {
  if (bunAutoAllowsScripts(install["auto"])) return true;
  const hasTrusted =
    bunfig["trustedDependencies"] !== undefined || install["trustedDependencies"] !== undefined;
  const hasSecurity = isPlainObject(install["security"]);
  const denyScripts =
    bunfig["ignoreScripts"] === true ||
    install["ignoreScripts"] === true ||
    bunfig["ignore-scripts"] === true ||
    install["ignore-scripts"] === true;
  return !hasTrusted && !hasSecurity && !denyScripts;
}

function bunAutoAllowsScripts(auto: unknown): boolean {
  if (auto === true) return true;
  if (typeof auto !== "string") return false;
  const value = auto.trim().toLowerCase();
  return value === "auto" || value === "force" || value === "fallback" || value === "true" || value === "all";
}

function bunRegistryPinned(install: Record<string, unknown>): boolean {
  const registry = install["registry"];
  if (hasText(registry)) return true;
  return isPlainObject(registry) && hasText(registry["url"]);
}

function bunLockfilePresent(project: Project, manager: DetectedManager, readFile: ReadFile): boolean {
  if (manager.lockfilePath !== null && readFile(manager.lockfilePath) !== null) return true;
  return (
    readFile(`${project.root}/bun.lock`) !== null || readFile(`${project.root}/bun.lockb`) !== null
  );
}

function parseToml(raw: string): Record<string, unknown> {
  if (raw.trim() === "") return {};
  try {
    const parsed: unknown = parseTomlRaw(raw);
    return isPlainObject(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function readUvConfig(project: Project, readFile: ReadFile): Record<string, unknown> {
  const pyproject = parseToml(readFile(`${project.root}/pyproject.toml`) ?? "");
  const tool = isPlainObject(pyproject["tool"]) ? pyproject["tool"] : {};
  const toolUv = isPlainObject(tool["uv"]) ? tool["uv"] : {};
  const uvToml = parseToml(readFile(`${project.root}/uv.toml`) ?? "");
  return { ...toolUv, ...uvToml };
}

function uvExcludeNewerMeets(value: unknown, minDays: number): boolean {
  if (typeof value === "number" && Number.isFinite(value)) return value >= minDays;
  if (typeof value !== "string") return false;
  const trimmed = value.trim();
  if (trimmed === "") return false;
  const asNumber = Number(trimmed);
  if (Number.isFinite(asNumber) && trimmed === String(asNumber)) return asNumber >= minDays;
  if (/[tT-]/.test(trimmed)) {
    const ts = Date.parse(trimmed);
    if (!Number.isNaN(ts)) return Date.now() - ts >= minDays * 86_400_000;
  }
  const hours = parsePnpmAgeHours(trimmed);
  return hours !== null && hours / 24 >= minDays;
}

function uvHasExtraIndexes(cfg: Record<string, unknown>): boolean {
  const extra = cfg["extra-index-url"];
  if (typeof extra === "string" && extra.trim() !== "") return true;
  if (Array.isArray(extra) && extra.length > 0) return true;
  const index = cfg["index"];
  if (!Array.isArray(index)) return false;
  if (index.length > 1) return true;
  return index.some((entry) => isPlainObject(entry) && entry["default"] !== true);
}

function defaultReadFile(path: string): string | null {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
}
