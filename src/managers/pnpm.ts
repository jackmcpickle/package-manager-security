import type { ManagerProfile } from "./profile";

export const pnpmProfile: ManagerProfile = {
  auditArgv: ["pnpm", "audit", "--json"],
  binary: "pnpm",
  configNames: ["pnpm-workspace.yaml"],
  kind: "config",
  lockfileNames: ["pnpm-lock.yaml"],
  name: "pnpm",
  upgradeArgv: (pkg, fixVersion) => ["pnpm", "add", `${pkg}@${fixVersion}`],
  writeConfigName: "pnpm-workspace.yaml",
};
