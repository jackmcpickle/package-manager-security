import type { ExitCode } from "./domain";

export async function run(
  argv: string[],
  deps?: {
    stdout: { write: (s: string) => unknown };
    stderr: { write: (s: string) => unknown };
    cwd: string;
    env: Record<string, string | undefined>;
  },
): Promise<{ exitCode: ExitCode }> {
  const stderr = deps?.stderr ?? process.stderr;
  stderr.write("Usage: pmsec <command>\n");
  return { exitCode: 2 };
}
