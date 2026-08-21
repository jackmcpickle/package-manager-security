import type { Finding, PackageManager, Project } from "./domain";
import { profileFor } from "./managers/profile";

export interface Preflight {
  missing: { manager: PackageManager; binary: string }[];
  warnings: Finding[];
}

export const preflight = (
  project: Project,
  opts: { which: (binary: string) => string | null }
): Preflight => {
  const missing: { manager: PackageManager; binary: string }[] = [];
  const warnings: Finding[] = [];

  for (const manager of project.managers) {
    if (manager.role !== "primary") {
      continue;
    }
    const { binary } = profileFor(manager.name);
    if (!binary) {
      continue;
    }
    if (opts.which(binary)) {
      continue;
    }

    missing.push({ binary, manager: manager.name });
    warnings.push({
      code: "pm.missing-binary",
      fixable: false,
      kind: "missing-binary",
      manager: manager.name,
      message: `Missing ${binary} binary for ${manager.name}`,
      path: manager.lockfilePath ?? manager.manifestPath,
      severity: "info",
    });
  }

  return { missing, warnings };
};
