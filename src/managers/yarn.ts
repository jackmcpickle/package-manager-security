import type { ManagerProfile } from "./profile";

export const yarnProfile: ManagerProfile = {
  auditArgv: ["yarn", "npm", "audit", "--json"],
  binary: "yarn",
  configNames: [".yarnrc.yml"],
  kind: "config",
  lockfileNames: ["yarn.lock"],
  name: "yarn",
  // yarn advisories have no auto-upgrade yet
  upgradeArgv: null,
  writeConfigName: ".yarnrc.yml",
};
