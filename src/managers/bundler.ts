import type { ManagerProfile } from "./profile";

export const bundlerProfile: ManagerProfile = {
  auditArgv: ["bundle-audit", "check", "--format", "json"],
  binary: "bundle-audit",
  configNames: [".bundle/config"],
  kind: "config",
  lockfileNames: ["Gemfile.lock"],
  name: "bundler",
  // bundler advisories have no auto-upgrade yet
  upgradeArgv: null,
  writeConfigName: ".bundle/config",
};
