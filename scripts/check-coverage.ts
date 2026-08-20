import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { compareCoverage, parseLcov, summarize, type CoverageSummary } from "./coverage";

const root = join(import.meta.dir, "..");
const lcovPath = join(root, "coverage/lcov.info");
const baselinePath = join(root, ".coverage-baseline");
const write = process.argv.includes("--write");

const raw = readFileSync(lcovPath, "utf8");
const current = summarize(parseLcov(raw));

if (write) {
  writeFileSync(baselinePath, `${JSON.stringify(current, null, 2)}\n`);
  process.stdout.write(`wrote ${baselinePath}\n`);
  process.exit(0);
}

const baseline = JSON.parse(readFileSync(baselinePath, "utf8")) as CoverageSummary;
const result = compareCoverage(current, baseline);
for (const message of result.messages) process.stderr.write(`${message}\n`);
if (!result.ok) process.exit(1);
