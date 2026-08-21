import type { ManagerProfile } from "./profile";

export const pipenvProfile: ManagerProfile = {
  auditArgv: null,
  binary: null,
  configNames: [],
  kind: "python-legacy",
  lockfileNames: ["Pipfile.lock"],
  name: "pipenv",
  upgradeArgv: null,
  writeConfigName: null,
};
