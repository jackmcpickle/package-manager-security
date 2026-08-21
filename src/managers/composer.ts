import type { ManagerProfile } from "./profile";

export const composerProfile: ManagerProfile = {
  auditArgv: ["composer", "audit", "--format", "json", "--locked"],
  binary: "composer",
  configNames: ["composer.json"],
  kind: "config",
  lockfileNames: ["composer.lock"],
  name: "composer",
  // composer advisories have no auto-upgrade yet
  upgradeArgv: null,
  writeConfigName: "composer.json",
};
