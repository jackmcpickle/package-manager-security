import type { ManagerProfile } from "./profile";

export const uvProfile: ManagerProfile = {
  auditArgv: ["uv", "audit", "--output-format", "json", "--frozen"],
  binary: "uv",
  // pyproject.toml counts only when it has a [tool.uv] table; that check
  // stays in apply-settings.ts / settings.ts where the parsing already lives.
  configNames: ["uv.toml", "pyproject.toml"],
  kind: "config",
  lockfileNames: ["uv.lock"],
  name: "uv",
  upgradeArgv: (pkg) => ["uv", "lock", "--upgrade-package", pkg],
  writeConfigName: null,
};
