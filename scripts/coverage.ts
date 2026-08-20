export type Counts = { hit: number; total: number };

export type CoverageSummary = {
  lines: Counts;
  functions: Counts;
  groups: {
    settings: Counts;
    apply: Counts;
  };
};

export type CompareResult = {
  ok: boolean;
  messages: string[];
};

const SETTINGS_FILES = new Set(["src/settings.ts"]);
const APPLY_FILES = new Set(["src/apply-settings.ts", "src/apply-advisories.ts"]);
export const FLOOR_PCT = 85;

export function parseLcov(raw: string): Map<string, { lines: Counts; functions: Counts }> {
  const files = new Map<string, { lines: Counts; functions: Counts }>();
  let path = "";
  let lines: Counts = { hit: 0, total: 0 };
  let functions: Counts = { hit: 0, total: 0 };

  const flush = () => {
    if (path === "") return;
    files.set(path, { lines, functions });
    path = "";
  };

  for (const line of raw.split(/\r?\n/)) {
    if (line.startsWith("SF:")) {
      flush();
      path = line.slice(3).trim();
      lines = { hit: 0, total: 0 };
      functions = { hit: 0, total: 0 };
      continue;
    }
    if (line.startsWith("LF:")) lines.total = Number(line.slice(3));
    else if (line.startsWith("LH:")) lines.hit = Number(line.slice(3));
    else if (line.startsWith("FNF:")) functions.total = Number(line.slice(4));
    else if (line.startsWith("FNH:")) functions.hit = Number(line.slice(4));
    else if (line === "end_of_record") flush();
  }
  return files;
}

export function summarize(files: Map<string, { lines: Counts; functions: Counts }>): CoverageSummary {
  const src = [...files.entries()].filter(([path]) => path.startsWith("src/") && !path.endsWith("main.ts"));
  const add = (into: Counts, from: Counts) => {
    into.hit += from.hit;
    into.total += from.total;
  };
  const lines: Counts = { hit: 0, total: 0 };
  const functions: Counts = { hit: 0, total: 0 };
  const settings: Counts = { hit: 0, total: 0 };
  const apply: Counts = { hit: 0, total: 0 };

  for (const [path, counts] of src) {
    add(lines, counts.lines);
    add(functions, counts.functions);
    if (SETTINGS_FILES.has(path)) add(settings, counts.lines);
    if (APPLY_FILES.has(path)) add(apply, counts.lines);
  }

  return { lines, functions, groups: { settings, apply } };
}

export function pct(counts: Counts): string {
  if (counts.total === 0) return "100.00";
  return ((counts.hit / counts.total) * 100).toFixed(2);
}

export function ratioDropped(current: Counts, baseline: Counts): boolean {
  return current.hit * baseline.total < baseline.hit * current.total;
}

export function belowFloor(counts: Counts, floor: number): boolean {
  return counts.total > 0 && (counts.hit / counts.total) * 100 < floor;
}

export function compareCoverage(
  current: CoverageSummary,
  baseline: CoverageSummary,
  floor = FLOOR_PCT,
): CompareResult {
  const messages: string[] = [];
  if (ratioDropped(current.lines, baseline.lines)) {
    messages.push(`line coverage dropped: ${pct(baseline.lines)}% → ${pct(current.lines)}%`);
  }
  if (ratioDropped(current.functions, baseline.functions)) {
    messages.push(
      `function coverage dropped: ${pct(baseline.functions)}% → ${pct(current.functions)}%`,
    );
  }
  if (belowFloor(current.groups.settings, floor)) {
    messages.push(`settings line coverage ${pct(current.groups.settings)}% is below the ${floor}% floor`);
  }
  if (belowFloor(current.groups.apply, floor)) {
    messages.push(`apply line coverage ${pct(current.groups.apply)}% is below the ${floor}% floor`);
  }
  if (messages.length === 0 && ratioDropped(baseline.lines, current.lines)) {
    messages.push(
      `line coverage rose: ${pct(baseline.lines)}% → ${pct(current.lines)}%. Run bun run coverage:write to raise the floor.`,
    );
  }
  return { ok: messages.every((message) => message.includes("rose")), messages };
}
