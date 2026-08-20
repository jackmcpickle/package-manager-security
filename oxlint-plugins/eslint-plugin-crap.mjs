// node_modules/eslint-plugin-crap/src/rule.ts
import { readFileSync, statSync } from "node:fs";
import { isAbsolute as isAbsolute2, resolve as resolve2 } from "node:path";

// node_modules/eslint-plugin-crap/src/complexity.ts
var LOGICAL_ASSIGNMENT_OPERATORS = new Set(["&&=", "||=", "??="]);
function isDecisionPoint(node) {
  switch (node.type) {
    case "IfStatement":
    case "ConditionalExpression":
    case "ForStatement":
    case "ForInStatement":
    case "ForOfStatement":
    case "WhileStatement":
    case "DoWhileStatement":
    case "CatchClause":
    case "LogicalExpression":
      return true;
    case "SwitchCase":
      return node.test != null;
    case "AssignmentExpression":
      return LOGICAL_ASSIGNMENT_OPERATORS.has(node.operator);
    default:
      return false;
  }
}
function countDecisionPoints(node) {
  let count = isDecisionPoint(node) ? 1 : 0;
  for (const [key, value] of Object.entries(node)) {
    if (key === "parent")
      continue;
    if (Array.isArray(value)) {
      for (const child of value) {
        if (child && typeof child === "object" && typeof child.type === "string") {
          count += countDecisionPoints(child);
        }
      }
    } else if (value && typeof value === "object" && typeof value.type === "string") {
      count += countDecisionPoints(value);
    }
  }
  return count;
}
function cyclomaticComplexity(fnNode) {
  return countDecisionPoints(fnNode) + 1;
}

// node_modules/eslint-plugin-crap/src/crap.ts
function crapScore(complexity, coveragePct) {
  const uncovered = 1 - coveragePct / 100;
  return complexity * complexity * uncovered ** 3 + complexity;
}

// node_modules/eslint-plugin-crap/src/lcov.ts
import { isAbsolute, resolve } from "node:path";
function parseLcov(text, root) {
  const files = new Map;
  let current = null;
  for (const rawLine of text.split(`
`)) {
    const line = rawLine.trim();
    if (line.startsWith("SF:")) {
      const path = line.slice(3);
      const abs = isAbsolute(path) ? path : resolve(root, path);
      current = files.get(abs) ?? new Map;
      files.set(abs, current);
    } else if (line.startsWith("DA:") && current) {
      const [lineNo, hits] = line.slice(3).split(",");
      current.set(Number(lineNo), Number(hits));
    } else if (line === "end_of_record") {
      current = null;
    }
  }
  return files;
}
function coverageForRange(lines, startLine, endLine) {
  let total = 0;
  let covered = 0;
  for (const [lineNo, hits] of lines) {
    if (lineNo >= startLine && lineNo <= endLine) {
      total += 1;
      if (hits > 0)
        covered += 1;
    }
  }
  if (total === 0)
    return null;
  return covered / total * 100;
}

// node_modules/eslint-plugin-crap/src/rule.ts
var DEFAULT_MAX_CRAP = 30;
var DEFAULT_LCOV_PATH = "coverage/lcov.info";
var lcovCache = new Map;
function loadLcov(lcovPath, root) {
  const abs = isAbsolute2(lcovPath) ? lcovPath : resolve2(root, lcovPath);
  let mtimeMs;
  try {
    mtimeMs = statSync(abs).mtimeMs;
  } catch {
    lcovCache.set(abs, null);
    return null;
  }
  const cached = lcovCache.get(abs);
  if (cached && cached.mtimeMs === mtimeMs)
    return cached.data;
  const data = parseLcov(readFileSync(abs, "utf8"), root);
  lcovCache.set(abs, { mtimeMs, data });
  return data;
}
function functionName(node) {
  if (node.id?.name)
    return node.id.name;
  const parent = node.parent;
  if (!parent)
    return "<anonymous>";
  if (parent.type === "VariableDeclarator" && parent.id?.name)
    return parent.id.name;
  if ((parent.type === "MethodDefinition" || parent.type === "Property" || parent.type === "PropertyDefinition") && !parent.computed) {
    return parent.key?.name ?? String(parent.key?.value ?? "<anonymous>");
  }
  if (parent.type === "AssignmentExpression" && parent.left?.type === "Identifier")
    return parent.left.name;
  return "<anonymous>";
}
var crapRule = {
  meta: {
    type: "suggestion",
    docs: {
      description: "Flag functions whose CRAP score (complexity² × (1 − coverage)³ + complexity) exceeds a threshold"
    },
    schema: [
      {
        type: "object",
        properties: {
          maxCrap: { type: "number", minimum: 0 },
          lcovPath: { type: "string" }
        },
        additionalProperties: false
      }
    ],
    messages: {
      tooCrappy: "'{{name}}' has a CRAP score of {{crap}} (complexity {{cc}}, coverage {{cov}}%) — max is {{max}}. Add tests or simplify."
    }
  },
  create(context) {
    const options = context.options?.[0] ?? {};
    const maxCrap = options.maxCrap ?? DEFAULT_MAX_CRAP;
    const lcovPath = options.lcovPath ?? DEFAULT_LCOV_PATH;
    const cwd = context.cwd ?? process.cwd();
    const lcov = loadLcov(lcovPath, cwd);
    if (!lcov)
      return {};
    const filename = context.physicalFilename ?? context.filename;
    const fileLines = lcov.get(isAbsolute2(filename) ? filename : resolve2(cwd, filename));
    if (!fileLines)
      return {};
    function checkFunction(node) {
      const coverage = coverageForRange(fileLines, node.loc.start.line, node.loc.end.line);
      if (coverage === null)
        return;
      const cc = cyclomaticComplexity(node);
      const crap = crapScore(cc, coverage);
      if (crap <= maxCrap)
        return;
      context.report({
        node: node.id ?? node,
        messageId: "tooCrappy",
        data: {
          name: functionName(node),
          crap: crap.toFixed(1),
          cc: String(cc),
          cov: coverage.toFixed(1),
          max: String(maxCrap)
        }
      });
    }
    return {
      FunctionDeclaration: checkFunction,
      FunctionExpression: checkFunction,
      ArrowFunctionExpression: checkFunction
    };
  }
};

// node_modules/eslint-plugin-crap/src/index.ts
var plugin = {
  meta: {
    name: "crap",
    version: "0.1.0"
  },
  rules: {
    crap: crapRule
  }
};
var src_default = plugin;
export {
  src_default as default
};
