import { expect, test } from "bun:test";

import {
  belowFloor,
  compareCoverage,
  parseLcov,
  pct,
  ratioDropped,
  summarize,
} from "../scripts/coverage";
import type { CoverageSummary } from "../scripts/coverage";

const SAMPLE = `TN:
SF:src/settings.ts
FNF:2
FNH:2
LF:100
LH:90
end_of_record
TN:
SF:src/apply-settings.ts
FNF:1
FNH:1
LF:80
LH:80
end_of_record
TN:
SF:src/apply-advisories.ts
FNF:1
FNH:1
LF:20
LH:10
end_of_record
TN:
SF:tests/settings.test.ts
FNF:5
FNH:5
LF:50
LH:50
end_of_record
`;

test("parseLcov and summarize ignore tests and keep settings/apply groups", () => {
  const summary = summarize(parseLcov(SAMPLE));
  expect(summary.lines).toEqual({ hit: 180, total: 200 });
  expect(summary.functions).toEqual({ hit: 4, total: 4 });
  expect(summary.groups.settings).toEqual({ hit: 90, total: 100 });
  expect(summary.groups.apply).toEqual({ hit: 90, total: 100 });
  expect(pct(summary.lines)).toBe("90.00");
});

test("ratioDropped is true only when the current ratio is lower", () => {
  expect(ratioDropped({ hit: 89, total: 100 }, { hit: 90, total: 100 })).toBe(
    true
  );
  expect(ratioDropped({ hit: 90, total: 100 }, { hit: 90, total: 100 })).toBe(
    false
  );
  expect(ratioDropped({ hit: 180, total: 200 }, { hit: 90, total: 100 })).toBe(
    false
  );
});

test("compareCoverage fails on a line-coverage drop and on a settings floor miss", () => {
  const baseline: CoverageSummary = {
    functions: { hit: 4, total: 4 },
    groups: {
      apply: { hit: 90, total: 100 },
      settings: { hit: 90, total: 100 },
    },
    lines: { hit: 190, total: 200 },
  };
  const dropped = compareCoverage(summarize(parseLcov(SAMPLE)), baseline);
  expect(dropped.ok).toBe(false);
  expect(
    dropped.messages.some((message) =>
      message.startsWith("line coverage dropped")
    )
  ).toBe(true);

  const lowSettings = compareCoverage(
    {
      functions: { hit: 4, total: 4 },
      groups: {
        apply: { hit: 90, total: 100 },
        settings: { hit: 80, total: 100 },
      },
      lines: { hit: 190, total: 200 },
    },
    baseline
  );
  expect(lowSettings.ok).toBe(false);
  expect(
    lowSettings.messages.some((message) =>
      message.includes("settings line coverage")
    )
  ).toBe(true);
  expect(belowFloor({ hit: 80, total: 100 }, 85)).toBe(true);
});
