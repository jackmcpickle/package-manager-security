import { createBunHost } from "./bun-host";
import { run } from "./cli";

const { exitCode } = await run(process.argv.slice(2), createBunHost());
process.exit(exitCode);
