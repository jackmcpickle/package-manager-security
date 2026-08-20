import type { Finding, PackageManager, Project } from "./domain";

export interface Preflight {
  missing: { manager: PackageManager; binary: string }[];
  warnings: Finding[];
}

const REQUIRED_BINARIES: Partial<Record<PackageManager, string>> = {
  npm: "npm",
  pnpm: "pnpm",
  yarn: "yarn",
  bun: "bun",
  uv: "uv",
};

export function preflight(
  project: Project,
  opts: { which: (binary: string) => string | null },
): Preflight {
  const missing: { manager: PackageManager; binary: string }[] = [];
  const warnings: Finding[] = [];

  for (const manager of project.managers) {
    if (manager.role !== "primary") continue;
    const binary = REQUIRED_BINARIES[manager.name];
    if (!binary) continue;
    if (opts.which(binary)) continue;

    missing.push({ manager: manager.name, binary });
    warnings.push({
      kind: "missing-binary",
      code: "pm.missing-binary",
      message: `Missing ${binary} binary for ${manager.name}`,
      severity: "info",
      path: manager.lockfilePath ?? manager.manifestPath,
      fixable: false,
      manager: manager.name,
    });
  }

  return { missing, warnings };
}
