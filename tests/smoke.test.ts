import { expect, test } from "bun:test";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ROOT = join(import.meta.dir, "..");
const FIXTURE = join(import.meta.dir, "fixtures/discover/many-repos");
const BINARY = join(ROOT, "dist/pmsec");

test(
  "compiled pmsec binary audits the many-repos fixture",
  async () => {
    mkdirSync(join(FIXTURE, "alpha/.git"), { recursive: true });
    mkdirSync(join(FIXTURE, "beta/.git"), { recursive: true });

    const build = Bun.spawnSync(["bun", "run", "build:binary"], {
      cwd: ROOT,
      stdout: "pipe",
      stderr: "pipe",
    });
    expect(build.exitCode).toBe(0);

    const bin = mkdtempSync(join(tmpdir(), "pmsec-smoke-bin-"));
    writeFileSync(join(bin, "npm"), `#!/bin/sh\necho '{"advisories":{}}'\n`);
    writeFileSync(join(bin, "pnpm"), `#!/bin/sh\necho '{"advisories":{}}'\n`);
    chmodSync(join(bin, "npm"), 0o755);
    chmodSync(join(bin, "pnpm"), 0o755);

    const proc = Bun.spawnSync([BINARY, "audit", FIXTURE, "--json"], {
      cwd: ROOT,
      stdout: "pipe",
      stderr: "pipe",
      env: {
        ...process.env,
        HOME: join(import.meta.dir, "fixtures/empty-home"),
        PATH: `${bin}:${process.env.PATH ?? ""}`,
      },
    });
    rmSync(bin, { recursive: true, force: true });

    const stdout = new TextDecoder().decode(proc.stdout);
    expect(stdout).toContain("scripts.unrestricted");
    expect(proc.exitCode).toBe(1);
  },
  { timeout: 120_000 },
);
