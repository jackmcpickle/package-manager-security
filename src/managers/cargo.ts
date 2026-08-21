import type { ManagerProfile } from "./profile";

export const cargoProfile: ManagerProfile = {
  auditArgv: ["cargo", "audit", "--json"],
  binary: "cargo",
  configNames: [".cargo/config.toml", ".cargo/config"],
  kind: "config",
  lockfileNames: ["Cargo.lock"],
  name: "cargo",
  // cargo advisories have no auto-upgrade yet
  upgradeArgv: null,
  writeConfigName: ".cargo/config.toml",
};
