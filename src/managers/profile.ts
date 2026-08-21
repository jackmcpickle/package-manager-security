import type { PackageManager } from "../domain";
import { bunProfile } from "./bun";
import { bundlerProfile } from "./bundler";
import { cargoProfile } from "./cargo";
import { composerProfile } from "./composer";
import { npmProfile } from "./npm";
import { pipProfile } from "./pip";
import { pipenvProfile } from "./pipenv";
import { pnpmProfile } from "./pnpm";
import { poetryProfile } from "./poetry";
import { uvProfile } from "./uv";
import { yarnProfile } from "./yarn";

export interface ManagerProfile {
  readonly name: PackageManager;
  /** "config" = auditable+fixable; "python-legacy" = flagged only (poetry/pip/pipenv) */
  readonly kind: "config" | "python-legacy";
  /** binary preflight checks for; null when none required (poetry/pip/pipenv, bundler uses bundle-audit) */
  readonly binary: string | null;
  /** native audit command; null → OSV path */
  readonly auditArgv: readonly string[] | null;
  /** argv to upgrade one package; null = advisories not auto-fixable for this manager */
  readonly upgradeArgv: ((pkg: string, fixVersion: string) => string[]) | null;
  /** lockfile basenames in priority order, e.g. ["bun.lock", "bun.lockb"] */
  readonly lockfileNames: readonly string[];
  /** default config file path(s) relative to project root, in read-priority order,
      e.g. npm [".npmrc"], cargo [".cargo/config.toml", ".cargo/config"], uv ["uv.toml", "pyproject.toml"] */
  readonly configNames: readonly string[];
  /** the config file apply-settings writes, relative to root; null = not writable via profile default */
  readonly writeConfigName: string | null;
}

const REGISTRY: Record<PackageManager, ManagerProfile> = {
  bun: bunProfile,
  bundler: bundlerProfile,
  cargo: cargoProfile,
  composer: composerProfile,
  npm: npmProfile,
  pip: pipProfile,
  pipenv: pipenvProfile,
  pnpm: pnpmProfile,
  poetry: poetryProfile,
  uv: uvProfile,
  yarn: yarnProfile,
};

export const profileFor = (name: PackageManager): ManagerProfile =>
  REGISTRY[name];

/** the 8 config-kind manager names, in the order the enabled-managers default used to list them */
export const CONFIG_MANAGER_NAMES: readonly PackageManager[] = [
  "npm",
  "pnpm",
  "yarn",
  "bun",
  "uv",
  "bundler",
  "cargo",
  "composer",
];
