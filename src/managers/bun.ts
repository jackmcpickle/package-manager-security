import type { ManagerProfile } from "./profile";

export const bunProfile: ManagerProfile = {
  auditArgv: ["bun", "audit", "--json"],
  binary: "bun",
  configNames: ["bunfig.toml"],
  kind: "config",
  lockfileNames: ["bun.lock", "bun.lockb"],
  name: "bun",
  // bun advisories have no auto-upgrade yet
  upgradeArgv: null,
  writeConfigName: "bunfig.toml",
};
