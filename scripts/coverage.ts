export interface Counts {
  hit: number;
  total: number;
}

export interface CoverageSummary {
  functions: Counts;
  groups: {
    apply: Counts;
    settings: Counts;
  };
  lines: Counts;
}

export interface CompareResult {
  messages: string[];
  ok: boolean;
}

const SETTINGS_FILES = new Set(["src/settings.ts"]);
const APPLY_FILES = new Set([
  "src/apply-advisories.ts",
  "src/apply-settings.ts",
]);
export const FLOOR_PCT = 85;

const emptyCounts = (): Counts => ({ hit: 0, total: 0 });

const addCounts = (into: Counts, from: Counts): void => {
  into.hit += from.hit;
  into.total += from.total;
};

const LCOV_METRIC: Record<
  string,
  (counts: { functions: Counts; lines: Counts }, value: number) => void
> = {
  FNF: (counts, value) => {
    counts.functions.total = value;
  },
  FNH: (counts, value) => {
    counts.functions.hit = value;
  },
  LF: (counts, value) => {
    counts.lines.total = value;
  },
  LH: (counts, value) => {
    counts.lines.hit = value;
  },
};

export const parseLcov = (
  raw: string
): Map<string, { functions: Counts; lines: Counts }> => {
  const files = new Map<string, { functions: Counts; lines: Counts }>();
  let filePath = "";
  let lines = emptyCounts();
  let functions = emptyCounts();

  const flush = (): void => {
    if (filePath === "") {
      return;
    }
    files.set(filePath, { functions, lines });
    filePath = "";
  };

  for (const line of raw.split(/\r?\n/u)) {
    if (line.startsWith("SF:")) {
      flush();
      filePath = line.slice(3).trim();
      lines = emptyCounts();
      functions = emptyCounts();
      continue;
    }
    if (line === "end_of_record") {
      flush();
      continue;
    }
    const prefix = line.slice(0, Math.max(line.indexOf(":"), 0));
    const apply = LCOV_METRIC[prefix];
    if (apply === undefined) {
      continue;
    }
    apply({ functions, lines }, Number(line.slice(prefix.length + 1)));
  }
  return files;
};

export const summarize = (
  files: Map<string, { functions: Counts; lines: Counts }>
): CoverageSummary => {
  const src = [...files.entries()].filter(
    ([filePath]) => filePath.startsWith("src/") && !filePath.endsWith("main.ts")
  );
  const lines = emptyCounts();
  const functions = emptyCounts();
  const settings = emptyCounts();
  const apply = emptyCounts();

  for (const [filePath, counts] of src) {
    addCounts(lines, counts.lines);
    addCounts(functions, counts.functions);
    if (SETTINGS_FILES.has(filePath)) {
      addCounts(settings, counts.lines);
    }
    if (APPLY_FILES.has(filePath)) {
      addCounts(apply, counts.lines);
    }
  }

  return { functions, groups: { apply, settings }, lines };
};

export const pct = (counts: Counts): string => {
  if (counts.total === 0) {
    return "100.00";
  }
  return ((counts.hit / counts.total) * 100).toFixed(2);
};

export const ratioDropped = (current: Counts, baseline: Counts): boolean =>
  current.hit * baseline.total < baseline.hit * current.total;

export const belowFloor = (counts: Counts, floor: number): boolean =>
  counts.total > 0 && (counts.hit / counts.total) * 100 < floor;

const dropMessage = (
  label: string,
  current: Counts,
  baseline: Counts
): string | undefined => {
  if (!ratioDropped(current, baseline)) {
    return undefined;
  }
  return `${label} dropped: ${pct(baseline)}% → ${pct(current)}%`;
};

const floorMessage = (
  label: string,
  counts: Counts,
  floor: number
): string | undefined => {
  if (!belowFloor(counts, floor)) {
    return undefined;
  }
  return `${label} ${pct(counts)}% is below the ${floor}% floor`;
};

export const compareCoverage = (
  current: CoverageSummary,
  baseline: CoverageSummary,
  floor = FLOOR_PCT
): CompareResult => {
  const messages = [
    dropMessage("line coverage", current.lines, baseline.lines),
    dropMessage("function coverage", current.functions, baseline.functions),
    floorMessage("settings line coverage", current.groups.settings, floor),
    floorMessage("apply line coverage", current.groups.apply, floor),
  ].filter((message): message is string => message !== undefined);

  if (messages.length === 0 && ratioDropped(baseline.lines, current.lines)) {
    messages.push(
      `line coverage rose: ${pct(baseline.lines)}% → ${pct(current.lines)}%. Run bun run coverage:write to raise the floor.`
    );
  }
  return {
    messages,
    ok: messages.every((message) => message.includes("rose")),
  };
};
