const LINE_BREAK = /\r?\n/u;

const stripQuotes = (value: string): string => {
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    return value.slice(1, -1);
  }
  return value;
};

const parseBundleLine = (
  line: string
): { key: string; value: string } | null => {
  const trimmed = line.trim();
  if (trimmed === "" || trimmed === "---" || trimmed.startsWith("#")) {
    return null;
  }
  const colon = trimmed.indexOf(":");
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
    lines.push(`${key}: "${value}"`);
  }
  return `${lines.join("\n")}\n`;
};
