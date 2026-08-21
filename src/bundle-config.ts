const LINE_BREAK = /\r?\n/u;
const ESCAPED = /\\(?<char>["\\])/gu;
const BACKSLASH = /\\/gu;
const DOUBLE_QUOTE = /"/gu;

const unescapeDouble = (value: string): string =>
  value.replace(ESCAPED, "$<char>");

const escapeDouble = (value: string): string =>
  value.replace(BACKSLASH, "\\\\").replace(DOUBLE_QUOTE, '\\"');

const stripQuotes = (value: string): string => {
  if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
    return unescapeDouble(value.slice(1, -1));
  }
  if (value.length >= 2 && value.startsWith("'") && value.endsWith("'")) {
    return value.slice(1, -1);
  }
  return value;
};

/**
 * Index of the `key: value` separator. Bundler writes mirror keys such as
 * `BUNDLE_MIRROR__HTTPS://RUBYGEMS.ORG/`, so splitting on the first colon would
 * mangle them. Prefer a colon followed by a space, then a trailing colon
 * (empty value), and only then fall back to the first colon.
 */
const separatorIndex = (line: string): number => {
  const spaced = line.indexOf(": ");
  if (spaced > 0) {
    return spaced;
  }
  if (line.endsWith(":")) {
    return line.length - 1;
  }
  return line.indexOf(":");
};

const parseBundleLine = (
  line: string
): { key: string; value: string } | null => {
  const trimmed = line.trim();
  if (trimmed === "" || trimmed === "---" || trimmed.startsWith("#")) {
    return null;
  }
  const colon = separatorIndex(trimmed);
  if (colon <= 0) {
    return null;
  }
  const key = trimmed.slice(0, colon).trim();
  const value = stripQuotes(trimmed.slice(colon + 1).trim());
  return { key, value };
};

export const parseBundleConfig = (raw: string): Record<string, string> => {
  const out: Record<string, string> = {};
  for (const line of raw.split(LINE_BREAK)) {
    const parsed = parseBundleLine(line);
    if (parsed !== null) {
      out[parsed.key] = parsed.value;
    }
  }
  return out;
};

export const stringifyBundleConfig = (
  config: Record<string, string>
): string => {
  const lines = ["---"];
  for (const [key, value] of Object.entries(config)) {
    lines.push(`${key}: "${escapeDouble(value)}"`);
  }
  return `${lines.join("\n")}\n`;
};
