import { defineConfig } from "oxlint";
import core from "ultracite/oxlint/core";

const ignorePatterns = [
  ...core.ignorePatterns,
  "oxlint-plugins/**",
  "tests/fixtures/**",
];

export default defineConfig({
  env: {
    ...core.env,
    node: true,
  },
  extends: [core],
  ignorePatterns,
  // Published package ships TypeScript; oxlint's Node loader cannot strip
  // types under node_modules, so we load the bundled copy instead.
  jsPlugins: ["./oxlint-plugins/eslint-plugin-crap.mjs"],
  rules: {
    "crap/crap": ["warn", { lcovPath: "coverage/lcov.info", maxCrap: 30 }],
  },
});
