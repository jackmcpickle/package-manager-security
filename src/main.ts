import { run } from "./cli";

const { exitCode } = await run(process.argv.slice(2));
process.exit(exitCode);
