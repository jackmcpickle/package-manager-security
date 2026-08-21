import type { ManagerProfile } from "./profile";

export const npmProfile: ManagerProfile = {
  auditArgv: ["npm", "audit", "--json"],
  binary: "npm",
  configNames: [".npmrc"],
  kind: "config",
  lockfileNames: ["package-lock.json"],
  name: "npm",
  upgradeArgv: (pkg, fixVersion) => [
    "npm",
    "install",
    `${pkg}@${fixVersion}`,
    "--save-exact",
  ],
  writeConfigName: ".npmrc",
};
