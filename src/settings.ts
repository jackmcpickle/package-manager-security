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
  const manifestRaw = readFile(manager.manifestPath);
  const findings: Finding[] = [];

  const scriptsIgnored = npmrc["ignore-scripts"] === "true";
  const allowScripts = isPlainObject(manifestField(manifestRaw, "allowScripts"));
  const strictAllowScripts = npmrc["strict-allow-scripts"] === "true";

  // An enforced package.json allowScripts policy is a valid, more precise
  // alternative to blanket ignore-scripts. It is only enforced once
  // strict-allow-scripts is on; until then npm 11 merely warns.
  if (settings.ignoreScripts && !scriptsIgnored && !(allowScripts && strictAllowScripts)) {
    findings.push(
      setting(
        "scripts.unrestricted",
        "npm ignore-scripts must be true, or allowScripts with strict-allow-scripts",
        "high",
        npmrcPath,
        "npm",
      ),
    );
  }

  if (settings.ignoreScripts && allowScripts && !strictAllowScripts) {
    findings.push(
      advice(
        "scripts.allowlist-advisory",
        "allowScripts is advisory until strict-allow-scripts=true (npm 12 default)",
        npmrcPath,
        "npm",
      ),
    );
  }

  // npm/cli#9450: ignore-scripts hides the allowScripts tooling entirely.
  if (scriptsIgnored && allowScripts) {
    findings.push(
      advice(
        "scripts.allowlist-masked",
        "ignore-scripts=true masks the package.json allowScripts policy",
        npmrcPath,
        "npm",
      ),
    );
  }

  if (settings.ignoreScripts && npmrcAllowsNonRegistry(npmrc)) {
    findings.push(
      setting(
        "source.non-registry",
        "allow-git and allow-remote must not be set to all",
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
  const version = managerVersion(readFile(manager.manifestPath), "pnpm");
  // pnpm >= 10 blocks dependency builds by default; pnpm >= 11 replaced the
  // onlyBuiltDependencies family with a single allowBuilds map.
  const buildsBlockedByDefault = atLeastOrUnknown(version, 10);
  const usesAllowBuilds = atLeastOrUnknown(version, 11);
  const findings: Finding[] = [];

  if (settings.ignoreScripts) {
    const hasAllowBuilds = isPlainObject(yaml["allowBuilds"]);
    const legacy = PNPM_LEGACY_BUILD_KEYS.filter((key) => yaml[key] !== undefined);

    if (yaml["dangerouslyAllowAllBuilds"] === true) {
      findings.push(
        setting(
          "scripts.unrestricted",
          "pnpm dangerouslyAllowAllBuilds must not be true",
          "high",
          yamlPath,
          "pnpm",
        ),
      );
    } else if (usesAllowBuilds && legacy.length > 0 && !hasAllowBuilds) {
      findings.push(
        setting(
          "scripts.legacy-config",
          `pnpm 11 removed ${legacy.join(", ")}; use allowBuilds instead`,
          "high",
          yamlPath,
          "pnpm",
        ),
      );
    } else if (!hasAllowBuilds && legacy.length === 0) {
      findings.push(
        buildsBlockedByDefault
          ? advice(
              "scripts.unrestricted",
              "pnpm blocks dependency builds by default; declare allowBuilds to review them explicitly",
              yamlPath,
              "pnpm",
              defaultRelianceSeverity(policy.preset),
              true,
            )
          : setting(
              "scripts.unrestricted",
              "pnpm builds must be restricted",
              "high",
              yamlPath,
              "pnpm",
            ),
      );
    }

    if (yaml["strictDepBuilds"] === false) {
      findings.push(
        setting(
          "scripts.non-strict",
          "pnpm strictDepBuilds must not be false",
          "high",
          yamlPath,
          "pnpm",
        ),
      );
    }
  }

  if (yaml["blockExoticSubdeps"] === false) {
    findings.push(
      setting(
        "source.non-registry",
        "pnpm blockExoticSubdeps must not be false",
        "high",
        yamlPath,
        "pnpm",
      ),
    );
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
    const raw = yaml["minimumReleaseAge"];
    const explicit = raw !== undefined;
    // pnpm 11 ships minimumReleaseAge=1440 (24h) on by default.
    const defaultHours = usesAllowBuilds ? 24 : 0;
    const hours = explicit ? parsePnpmAgeHours(raw) : defaultHours;
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

    // minimumReleaseAgeStrict defaults to true only when the gate is set
    // explicitly; false lets pnpm fall back to a version that fails the gate.
    if (yaml["minimumReleaseAgeStrict"] === false) {
      findings.push(
        setting(
          "min-age.non-strict",
          "pnpm minimumReleaseAgeStrict must not be false",
          "high",
          yamlPath,
          "pnpm",
        ),
      );
    }

    if (isBlanketExclude(yaml["minimumReleaseAgeExclude"])) {
      findings.push(
        setting(
          "min-age.exclude-all",
          "minimumReleaseAgeExclude must not exempt every package",
          "high",
          yamlPath,
          "pnpm",
        ),
      );
    }

    if (policy.preset === "strict" && yaml["minimumReleaseAgeIgnoreMissingTime"] !== false) {
      findings.push(
        setting(
          "min-age.missing-time",
          "minimumReleaseAgeIgnoreMissingTime must be false to fail closed",
          "moderate",
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
  const version = managerVersion(readFile(manager.manifestPath), "yarn");
  // Yarn stopped running dependency postinstalls by default in 4.14, and
  // added npmMinimalAgeGate (default 1w) in 4.12.
  const scriptsOffByDefault = atLeastOrUnknown(version, 4, 14);
  const ageGateByDefault = atLeastOrUnknown(version, 4, 12);
  const findings: Finding[] = [];

  if (settings.ignoreScripts && yarnrc["enableScripts"] !== false) {
    findings.push(
      yarnrc["enableScripts"] === true || !scriptsOffByDefault
        ? setting(
            "scripts.unrestricted",
            "yarn enableScripts must be false",
            "high",
            yarnrcPath,
            "yarn",
          )
        : advice(
            "scripts.unrestricted",
            "yarn defaults enableScripts to false; set it explicitly to keep that guarantee",
            yarnrcPath,
            "yarn",
            defaultRelianceSeverity(policy.preset),
            true,
          ),
    );
  }

  if (settings.minReleaseAgeDays > 0) {
    const raw = yarnrc["npmMinimalAgeGate"];
    const defaultHours = ageGateByDefault ? 24 * 7 : 0;
    const hours = raw === undefined ? defaultHours : parsePnpmAgeHours(raw);
    const requiredHours = settings.minReleaseAgeDays * 24;
    if (hours === null || hours < requiredHours) {
      findings.push(
        setting(
          "min-age.disabled",
          `npmMinimalAgeGate must be at least ${requiredHours * 60} minutes`,
          "high",
          yarnrcPath,
          "yarn",
        ),
      );
    }

    if (isBlanketExclude(yarnrc["npmPreapprovedPackages"])) {
      findings.push(
        setting(
          "min-age.exclude-all",
          "npmPreapprovedPackages must not exempt every package",
          "high",
          yarnrcPath,
          "yarn",
        ),
      );
    }
  }

  if (yarnrc["checksumBehavior"] !== undefined && yarnrc["checksumBehavior"] !== "throw") {
    findings.push(
      setting(
        "integrity.checksum-relaxed",
        'yarn checksumBehavior must be "throw"',
        "high",
        yarnrcPath,
        "yarn",
      ),
    );
  }

  if (yarnrc["enableStrictSsl"] === false) {
    findings.push(
      setting(
        "integrity.strict-ssl",
        "yarn enableStrictSsl must not be false",
        "high",
        yarnrcPath,
        "yarn",
      ),
    );
  }

  if (yarnrc["enableHardenedMode"] === false) {
    findings.push(
      setting(
        "integrity.hardened-mode",
        "yarn enableHardenedMode must not be false",
        "moderate",
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

  if (settings.minReleaseAgeDays > 0) {
    // bun expresses minimumReleaseAge in SECONDS and ships it off by default.
    const seconds = parseNumber(install["minimumReleaseAge"]);
    const requiredSeconds = settings.minReleaseAgeDays * 86_400;
    if (seconds === null || seconds < requiredSeconds) {
      findings.push(
        setting(
          "min-age.disabled",
          `install.minimumReleaseAge must be at least ${requiredSeconds} seconds`,
          "high",
          bunfigPath,
          "bun",
        ),
      );
    }

    if (isBlanketExclude(install["minimumReleaseAgeExcludes"])) {
      findings.push(
        setting(
          "min-age.exclude-all",
          "minimumReleaseAgeExcludes must not exempt every package",
          "high",
          bunfigPath,
          "bun",
        ),
      );
    }
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

  if (settings.minReleaseAgeDays > 0) {
    if (!uvExcludeNewerMeets(cfg["exclude-newer"], settings.minReleaseAgeDays)) {
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

    if (isBlanketExclude(cfg["exclude-newer-package"])) {
      findings.push(
        setting(
          "min-age.exclude-all",
          "exclude-newer-package must not exempt every package",
          "high",
          configPath,
          "uv",
        ),
      );
    }
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

/**
 * A finding that flags a weaker-than-ideal but not broken configuration —
 * typically relying on a safe default instead of pinning it explicitly.
 * Those are safe to write automatically; notes needing human judgement are not.
 */
function advice(
  code: string,
  message: string,
  path: string,
  manager: PackageManager,
  severity: Severity = "info",
  fixable = false,
): Finding {
  return { kind: "settings", code, message, severity, path, fixable, manager };
}

const PNPM_LEGACY_BUILD_KEYS = [
  "onlyBuiltDependencies",
  "onlyBuiltDependenciesFile",
  "neverBuiltDependencies",
  "ignoredBuiltDependencies",
  "ignoreDepScripts",
] as const;

type ManagerVersion = { major: number; minor: number };

/** Reads the pinned version out of package.json `packageManager`. */
function managerVersion(raw: string | null, name: string): ManagerVersion | null {
  const field = manifestField(raw, "packageManager");
  if (typeof field !== "string") return null;
  const match = field.match(/^([a-z]+)@(\d+)\.(\d+)/);
  if (match === null || match[1] !== name) return null;
  return { major: Number(match[2]), minor: Number(match[3]) };
}

/**
 * True when the pinned version is at least `major.minor`, or when no version is
 * pinned at all — an unpinned repo is assumed to be on a current release, and
 * `pm.unpinned` already nags about the missing pin.
 */
function atLeastOrUnknown(
  version: ManagerVersion | null,
  major: number,
  minor = 0,
): boolean {
  if (version === null) return true;
  if (version.major !== major) return version.major > major;
  return version.minor >= minor;
}

function defaultRelianceSeverity(preset: PresetName): Severity {
  return preset === "strict" ? "moderate" : "info";
}

/** True when an exclude list uses a bare wildcard, which voids the gate. */
function isBlanketExclude(value: unknown): boolean {
  const isStar = (entry: unknown) => typeof entry === "string" && /^\*+$/.test(entry.trim());
  if (isStar(value)) return true;
  if (Array.isArray(value)) return value.some(isStar);
  if (isPlainObject(value)) return Object.keys(value).some(isStar);
  return false;
}

function manifestField(raw: string | null, key: string): unknown {
  if (raw === null) return undefined;
  try {
    const parsed: unknown = JSON.parse(raw);
    return isPlainObject(parsed) ? parsed[key] : undefined;
  } catch {
    return undefined;
  }
}

/** npm 12 defaults allow-git and allow-remote to "none". */
function npmrcAllowsNonRegistry(npmrc: Record<string, string>): boolean {
  return npmrc["allow-git"] === "all" || npmrc["allow-remote"] === "all";
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
