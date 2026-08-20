import { expect, test } from "bun:test";
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
