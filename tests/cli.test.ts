import { expect, test } from "bun:test";
import { join } from "node:path";
import { run } from "../src/cli";

test("pmsec with no args prints usage and exits 2", async () => {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const result = await run([], {
    stdout: { write: (s: string) => stdout.push(s) },
    stderr: { write: (s: string) => stderr.push(s) },
    cwd: process.cwd(),
    env: {},
  });
  expect(result.exitCode).toBe(2);
  expect(stderr.join("")).toContain("Usage: pmsec");
});

test("audit of a fixture repo with open npm scripts exits 1 and lists the finding", async () => {
  const root = join(import.meta.dir, "fixtures/discover/many-repos/alpha");
  const stdout: string[] = [];
  const stderr: string[] = [];
  const result = await run(["audit", root], {
    stdout: { write: (s: string) => stdout.push(s) },
    stderr: { write: (s: string) => stderr.push(s) },
    cwd: import.meta.dir,
    env: { HOME: join(import.meta.dir, "fixtures/empty-home") },
  });
  expect(result.exitCode).toBe(1);
  expect(stdout.join("")).toContain("scripts.unrestricted");
});

test("CLI --preset wins over repo .pmsec.toml preset", async () => {
  const root = join(import.meta.dir, "fixtures/audit/flag-wins");
  const stdout: string[] = [];
  const stderr: string[] = [];
  const result = await run(["audit", root, "--preset", "relaxed"], {
    stdout: { write: (s: string) => stdout.push(s) },
    stderr: { write: (s: string) => stderr.push(s) },
    cwd: import.meta.dir,
    env: { HOME: join(import.meta.dir, "fixtures/empty-home") },
  });
  expect(stdout.join("")).not.toContain("scripts.unrestricted");
  expect(result.exitCode).toBe(0);
});
